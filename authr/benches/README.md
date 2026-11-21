# Authr Benchmarks

This document describes the performance benchmarks for Authr, including how to run them and the latest recorded results.

## Running Benchmarks

Database benchmarks require a dedicated MySQL database. Set the following environment variable before running them:

```powershell
$env:AUTHR_BENCH_DATABASE_URL = "mysql://user:password@localhost/authr_bench"
```

The database adapter initializes the schema and runs migrations automatically. Before each database benchmark suite, the benchmark database is reset by truncating its tables.

**Important:** Never point `AUTHR_BENCH_DATABASE_URL` at a production database or a database containing data you need to preserve.

## Latest Results

### Crypto

| Operation | Estimated time |
|---|---:|
| Derive secrets | **6.496 µs** |
| Hash session token | **7.648 µs** |
| Hash password | **41.212 ms** |
| Verify password | **41.350 ms** |

### Database

#### Users

| Operation | Estimated time |
|---|---:|
| Create | **2.252 ms** |
| Find by ID | **528.260 µs** |
| Find by email | **548.170 µs** |
| Update | **2.625 ms** |
| Delete by ID | **2.380 ms** |
| Delete by email | **2.435 ms** |

#### Sessions

| Operation | Estimated time |
|---|---:|
| Create | **2.335 ms** |
| Find by token | **572.760 µs** |
| Find by user ID | **31.200 ms** |
| Find other sessions | **23.179 ms** |
| Update | **2.563 ms** |
| Delete by token | **2.363 ms** |
| Delete user sessions | **2.446 ms** |
| Delete other sessions | **2.511 ms** |

#### Accounts

| Operation | Estimated time |
|---|---:|
| Create | **2.405 ms** |
| Find by ID | **561.340 µs** |
| Find by provider | **583.170 µs** |
| Find by user ID | **613.120 µs** |
| Find many by user ID | **620.080 µs** |
| Update | **2.726 ms** |
| Delete by ID | **2.334 ms** |
| Delete by user ID | **2.388 ms** |

#### Verifications

| Operation | Estimated time |
|---|---:|
| Create | **2.287 ms** |
| Find by ID | **529.450 µs** |
| Find by identifier | **582.550 µs** |
| Update | **2.636 ms** |
| Delete by ID | **2.415 ms** |
| Delete by identifier | **2.325 ms** |
| Consume | **3.822 ms** |

### Auth

| Operation | Estimated time |
|---|---:|
| Sign up | **50.284 ms** |
| Email sign in | **45.530 ms** |

### Middleware

| Operation | Estimated time |
|---|---:|
| Without session | **4.347 µs** |
| With session | **1.712 ms** |
