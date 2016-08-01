.PHONY: docker
docker:
	@docker build -t cloudflare/redoctober:$(shell git rev-parse --short HEAD) .
	@docker tag cloudflare/redoctober:$(shell git rev-parse --short HEAD) cloudflare/redoctober:latest
