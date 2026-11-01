#!/usr/bin/env python3
"""Train reproducible native LightGBM Huber fixtures, with/without Smart scaling."""
import argparse
import hashlib
import json
import pathlib
import lightgbm as lgb
import numpy as np

p=argparse.ArgumentParser();p.add_argument('--base-model',required=True);p.add_argument('--output-dir',required=True);args=p.parse_args()
root=pathlib.Path(args.output_dir);root.mkdir(parents=True,exist_ok=True)
names=pathlib.Path(args.base_model).read_text().split('feature_names=',1)[1].splitlines()[0].split()
rng=np.random.default_rng(20261101);data=rng.normal(size=(4096,len(names)))
labels=.6+.15*np.tanh(data[:,2])+.1*np.tanh(data[:,3])+.05*data[:,17];labels[::29]+=5
model=lgb.train(dict(objective='huber',alpha=.85,verbosity=-1,num_threads=1,seed=20261101,num_leaves=15,learning_rate=.07,min_data_in_leaf=12),lgb.Dataset(data,label=labels,feature_name=names),num_boost_round=40)
raw=root/'huber.bin';model.save_model(str(raw))
scaled=root/'huber-scaled.bin';scaled.write_text(raw.read_text()+'\n[transforms]\ntransform=true\n[definitions]\nstd_type=StandardScaler\nstd_features=2,3\nstd_mean=400,1200\nstd_scale=200,600\n[/definitions]\n[/transforms]\n')
result=dict(reference='LightGBM '+lgb.__version__,seed=20261101,trees=40,features=names,models={path.name:dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size) for path in [raw,scaled]})
(root/'manifest.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
