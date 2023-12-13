---
title: "Apiset forwarders"
---

API sets, or ApiSets, are a mechanism introduced in Windows operating systems to manage the way system libraries and APIs are organized and presented. They help in versioning and compatibility across different Windows versions.

Instead of directly calling a specific DLL (Dynamic Link Library) or API (Application Programming Interface), programs can use an "API set" name, which serves as a logical grouping for related functionality. This abstraction allows Microsoft to update underlying DLLs without breaking applications that rely on those APIs.

In essence, API sets provide a layer of indirection, enhancing flexibility and maintaining compatibility between different versions of Windows.

ApiSet names that begin with `api-` are guaranteeed to exist on all Windows versions.
Names that begin with `ext-` may not exist on all Windows versions.


{{< apisetschema_list >}}

