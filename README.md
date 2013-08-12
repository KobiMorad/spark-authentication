Spark Authentication
====================

[![Build Status](https://travis-ci.org/qmetric/spark-authentication.png)](https://travis-ci.org/qmetric/spark-authentication)

Authentication library for [Spark](http://www.sparkjava.com/) - included:

* [Basic authentication](http://en.wikipedia.org/wiki/Basic_access_authentication)


Usage
=====

Configure basic authentication for your given path(s):

```java
before(new BasicAuthenticationFilter("/path/*", new AuthenticationDetails("expected-username", "expected-password")));
```


Maven
=====
Library available from [Maven central repository](http://search.maven.org/)

```
<dependency>
    <groupId>com.qmetric</groupId>
    <artifactId>spark-authentication</artifactId>
    <version>${VERSION}</version>
</dependency>
```
