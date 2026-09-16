# proxy

nginx 1.27 serving the Angular build and proxying `/api/*`. The nginx config lives in
`../k8s/nginx.conf` (single source of truth: baked into the image and mounted from the
`proxy-nginx-conf` ConfigMap). Build from the `faultlab/` directory:

    docker build -f proxy/Dockerfile -t faultlab/proxy:dev .
