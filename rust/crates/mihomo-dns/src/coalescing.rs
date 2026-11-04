use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::DnsError;

type QueryResult = Result<Option<Vec<u8>>, DnsError>;
type QueryKey = (usize, Vec<u8>);

#[derive(Default)]
struct Flight {
    result: Mutex<Option<QueryResult>>,
    ready: Condvar,
}

/// Shares only overlapping queries. The complete wire request, including EDNS,
/// flags and question case, is part of the key; only the transaction ID differs.
/// Resolver generations have independent scopes, so a reload cannot reuse an
/// answer from a previous DNS policy. Completed answers are not cached here.
#[derive(Default)]
pub struct SharedDnsQueries {
    flights: Mutex<HashMap<QueryKey, Arc<Flight>>>,
}

impl SharedDnsQueries {
    pub fn resolve(
        &self,
        scope: usize,
        request: &[u8],
        resolve: impl FnOnce() -> QueryResult,
    ) -> QueryResult {
        // Bound retained keys on small routers. Oversized requests and a full
        // table keep the ordinary resolver behavior without adding state.
        if !(12..=4096).contains(&request.len()) {
            return resolve();
        }
        let mut packet = request.to_vec();
        packet[..2].fill(0);
        let key = (scope, packet);
        let (flight, leader) = {
            let mut flights = self.flights.lock().unwrap();
            if let Some(flight) = flights.get(&key) {
                (Arc::clone(flight), false)
            } else if flights.len() >= 256 {
                drop(flights);
                return resolve();
            } else {
                let flight = Arc::new(Flight::default());
                flights.insert(key.clone(), Arc::clone(&flight));
                (flight, true)
            }
        };

        let result = if leader {
            let mut owner = QueryOwner {
                queries: self,
                key,
                flight,
                completed: false,
            };
            let result = resolve().map(|response| {
                response.map(|mut response| {
                    if response.len() >= 2 {
                        response[..2].fill(0);
                    }
                    response
                })
            });
            owner.publish(result.clone());
            result
        } else {
            let (state, _) = flight
                .ready
                .wait_timeout_while(
                    flight.result.lock().unwrap(),
                    Duration::from_secs(30),
                    |result| result.is_none(),
                )
                .unwrap();
            state.clone().unwrap_or_else(|| {
                Err(DnsError::Io(
                    "timed out waiting for the shared DNS query".into(),
                ))
            })
        };
        result.map(|response| {
            response.map(|mut response| {
                if response.len() >= 2 {
                    response[..2].copy_from_slice(&request[..2]);
                }
                response
            })
        })
    }
}

struct QueryOwner<'a> {
    queries: &'a SharedDnsQueries,
    key: QueryKey,
    flight: Arc<Flight>,
    completed: bool,
}

impl QueryOwner<'_> {
    fn publish(&mut self, result: QueryResult) {
        *self
            .flight
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(result);
        self.flight.ready.notify_all();
        self.queries
            .flights
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.key);
        self.completed = true;
    }
}

impl Drop for QueryOwner<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // A failed worker must not leave followers waiting or retain its
            // key forever. No resolver I/O runs while a shared mutex is held.
            self.publish(Err(DnsError::Io("shared DNS query worker aborted".into())));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn concurrent_queries_share_io_and_keep_their_transaction_ids() {
        let queries = Arc::new(SharedDnsQueries::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(16));
        let workers: Vec<_> = (0u16..16)
            .map(|id| {
                let (queries, calls, barrier) = (queries.clone(), calls.clone(), barrier.clone());
                thread::spawn(move || {
                    let mut request = vec![0; 12];
                    request[..2].copy_from_slice(&id.to_be_bytes());
                    barrier.wait();
                    let response = queries
                        .resolve(1, &request, || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            thread::sleep(Duration::from_millis(100));
                            Ok(Some(vec![0; 12]))
                        })
                        .unwrap()
                        .unwrap();
                    assert_eq!(&response[..2], &id.to_be_bytes());
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(queries.flights.lock().unwrap().is_empty());
    }

    #[test]
    fn finished_answers_and_errors_are_not_retained_as_a_cache() {
        let queries = SharedDnsQueries::default();
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            assert!(queries
                .resolve(1, &[0; 12], || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(DnsError::Io("upstream unavailable".into()))
                })
                .is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(queries.flights.lock().unwrap().is_empty());
    }

    #[test]
    fn resolver_generation_and_wire_options_do_not_share_answers() {
        for different_scope in [false, true] {
            let queries = Arc::new(SharedDnsQueries::default());
            let barrier = Arc::new(Barrier::new(2));
            let workers: Vec<_> = (0..2u8)
                .map(|index| {
                    let (queries, barrier) = (queries.clone(), barrier.clone());
                    thread::spawn(move || {
                        let mut request = vec![0; 12];
                        if !different_scope {
                            request.extend_from_slice(&[index]);
                        }
                        barrier.wait();
                        let response = queries
                            .resolve(
                                if different_scope { index as usize } else { 0 },
                                &request,
                                || {
                                    thread::sleep(Duration::from_millis(100));
                                    let mut response = vec![0; 12];
                                    response.push(index);
                                    Ok(Some(response))
                                },
                            )
                            .unwrap()
                            .unwrap();
                        assert_eq!(response[12], index);
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        }
    }

    #[test]
    fn leader_panic_releases_the_key_and_notifies_followers() {
        let queries = Arc::new(SharedDnsQueries::default());
        let started = Arc::new(Barrier::new(2));
        let leader = {
            let (queries, started) = (queries.clone(), started.clone());
            thread::spawn(move || {
                queries.resolve(1, &[0; 12], || {
                    started.wait();
                    thread::sleep(Duration::from_millis(100));
                    panic!("resolver worker failed");
                })
            })
        };
        started.wait();
        let error = queries
            .resolve(1, &[0; 12], || panic!("must join the leader"))
            .unwrap_err();
        assert!(error.to_string().contains("worker aborted"));
        assert!(leader.join().is_err());
        assert!(queries.flights.lock().unwrap().is_empty());
    }
}
