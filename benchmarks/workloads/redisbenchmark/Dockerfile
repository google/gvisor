FROM redis:5.0.4
ENV host localhost
ENV port 6379
CMD ["sh", "-c", "redis-benchmark --csv -h ${host} -p ${port} ${flags}"]
