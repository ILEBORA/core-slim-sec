# Bora Core Slim Sec - Helper Framework

⚠️ **Disclaimer:** This repository contains only the helper framework (`Helpers.php`, `CoreDefaults.php`, `EnvLoader.php`, utility functions, and templating logic).  

The actual **Bora Core engine** is **encrypted and never included in this repository**. This means the repo does not contain sensitive business logic or secret keys.

---

## Overview

This framework provides:

- Utility functions for sessions, database access, API handling, and templating.
- Environment and error management.
- Basic helper classes for application development.

It is meant to be used **alongside the encrypted Bora Core engine**.

---

## Requirements

- PHP 8.2+
- Composer
- A valid Bora Core license with credentials (`CORE_CLIENT_ID`, `CORE_CLIENT_SECRET`, `CORE_CLIENT_IV`)
- `.env` file configured outside the repo:

```dotenv
CORE_CLIENT_ID=your-client-id
CORE_CLIENT_SECRET=your-secret-key
CORE_CLIENT_IV=your-initialization-vector
CORE_CACHE_PATH=/path/to/cache
