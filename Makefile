build:
	go build  -o razor-gen cmd/gen/main.go
	go build  -o razor cmd/runner/main.go


clean:
	rm razor
	rm razor-gen
