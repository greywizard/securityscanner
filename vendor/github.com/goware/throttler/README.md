# Throttler
[Golang](http://golang.org/) [HTTP](http://golang.org/pkg/net/http/) middleware to throttle the number of requests processed at a time.

[![GoDoc](https://godoc.org/github.com/goware/throttler?status.png)](https://godoc.org/github.com/goware/throttler)
[![Travis](https://travis-ci.org/goware/throttler.svg?branch=master)](https://travis-ci.org/goware/throttler)

## Usage

1. [Goji](#goji)
2. [Interpose](#interpose)
3. [Alice](#alice)
4. [Gorilla/mux](#gorillamux)
5. [DefaultServeMux (net/http)](#defaultservemux-nethttp)
6. [Chi](#chi)
7. ...don't see your favorite router/framework? We accept [Pull Requests](https://github.com/goware/throttler/pulls)!

### [Goji](https://github.com/zenazn/goji)

```go
// Limit to 5 requests globally.
goji.Use(throttler.Limit(5))

// Limit /admin route to 2 requests.
admin := web.New()
admin.Use(throttler.Limit(2))
admin.Get("/*", handler)
```

See [full example](./_examples/goji/main.go).

### [Interpose](https://github.com/carbocation/interpose)

```go
// Limit to 5 requests globally.
middle := interpose.New()
middle.Use(throttler.Limit(5))
```

See [full example](./_examples/interpose/main.go).

### [Alice](https://github.com/justinas/alice)

```go
// Limit to 5 requests globally.
chain := alice.New(throttler.Limit(5)).Then(handlerFunc)
```

See [full example](./_examples/alice/main.go).

### [Gorilla/mux](https://github.com/gorilla/mux)

```go
r := mux.NewRouter()
r.HandleFunc("/", handler)

// Limit to 5 requests globally.
limit := throttler.Limit(5)
http.Handle("/", limit(r))
```

See [full example](./_examples/gorilla/main.go).

### [DefaultServeMux (net/http)](http://golang.org/pkg/net/http/#ServeMux)

```go
// Limit to 5 requests globally.
limit := throttler.Limit(5)
http.Handle("/", limit(handlerFunc))

```

See [full example](./_examples/mux/main.go).

### [Chi](https://github.com/pressly/chi)

```go
r := chi.NewRouter()

// Limit to 5 requests globally.
r.Use(throttler.Limit(5))
r.Get("/*", handler)

// Limit to 2 requests for admin sub-router
admin := chi.NewRouter()
admin.Use(throttler.Limit(2))
```

See [full example](./_examples/chi/main.go).

## License
Throttler is licensed under the [MIT License](./LICENSE).
