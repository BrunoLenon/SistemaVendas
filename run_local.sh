export PORT=5000
gunicorn --bind 0.0.0.0:$PORT \
--workers 1 \
--threads 2 \
--timeout 95 \
--access-logfile - \
--error-logfile - \
--log-level debug \
--capture-output \
wsgi:app