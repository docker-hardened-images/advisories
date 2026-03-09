#!/usr/bin/env python3
"""
Simple Flask application for DHI scanner testing.
This demonstrates a derived DHI image with customer-added packages.
"""

from flask import Flask, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def hello():
    return jsonify({
        'message': 'Hello from DHI-derived image!',
        'base': 'dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51',
        'packages': ['flask==2.3.0', 'requests==2.31.0']
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
