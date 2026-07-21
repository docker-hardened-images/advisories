FROM dhi.io/python:3.13-alpine3.23-dev@sha256:dc755b8ac42aca1c64b6083374c217f0a569ae58c7909297f8052ee60839e4f6 AS builder

# Install customer dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --prefix /tmp/install -r requirements.txt

FROM dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51 AS runtime

# Copy dependencies and application
COPY --from=builder /tmp/install /opt/python
COPY app.py .

# Run the application
CMD ["python", "app.py"]
