# Stage one, build the application
FROM golang:1.9-alpine as build
MAINTAINER David Bainbridge <dbainbri@ciena.com>

# Need git to fetch dependancies, I guess vendoring could be used
RUN apk --update add git

# Copy in the source
WORKDIR /go/src
COPY . /go/src/github.com/ciena/oftee

# Build with everything statically linked
ENV CGO_ENABLED=0
RUN go install github.com/ciena/oftee

# Stage two, create the runtime image
FROM scratch
COPY --from=build /go/bin/oftee /oftee

# Run as nobody, because you can't be sure of which GID/UID to use
# and people should start a container with --user
COPY --from=build /etc/passwd /etc/passwd
USER nobody

# Start the tee
ENTRYPOINT ["/oftee"]
