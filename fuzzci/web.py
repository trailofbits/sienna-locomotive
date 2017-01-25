from flask import Flask
import fuzz
import json
import os

app = Flask('Sienna Locomotive 2')

@app.route('/')
def root():
    return 'choo?'

@app.route('/retest/', defaults={'target': None})
@app.route('/retest/<target>')
def retest(target):
    # TODO: this should be in a worker
    os.chdir('../sample/')
    if target is None:
        results = fuzz.test_all_targets()
    else:
        results = fuzz.test_one_target(target)

    return json.dumps(results)