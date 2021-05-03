#!/bin/bash
exec slirp-fullbolt \
	"host addr ${HOST_IP}" \
	"redir ${INTERNAL_SERVICE_PORT} 1999" \
	"redir 2000 2000"
