# Browser upload client

Okuru ships tus-js-client 4.3.1 from its own origin. The browser asset is the unmodified `dist/tus.min.js` from the upstream npm tarball. The source map and license notices are adjacent to the script.

| Artifact | SHA-512 integrity |
| --- | --- |
| npm tarball | `sha512-ZLeYmjrkaU1fUsKbIi8JML52uAocjEZtBx4DKjRrqzrZa0O4MYwT6db+oqePlspV+FxXJAyFBc/L5gwUi2OFsg==` |
| Served JavaScript | `sha512-ANMDrIMUl7SJ3/ykWfb5U5ZluVTPwgUEDxxLVcHSE4ATJXqUEsdlfbhtnyoSZbsBNb/aLsFzO/iWZZZTlMWr+w==` |

On upgrade, compare the npm dist tag to the upstream release, verify the published tarball digest before extracting the local files, review advisories and license notices, and update the SHA-512 check and the corresponding template integrity attribute together. Run the browser transfer tests before enabling the new build.

The stable tus protocol is version 1.0.0. The script provides offset-based resumption. Okuru owns authorization, expiry, storage encryption, quotas and publication. A large file can save retransmission after an interrupted connection. Each chunk costs one HTTP request and one acknowledgement. Actual throughput depends on the network, proxy buffering and encrypted disk. No comparative throughput claim has been measured on the production service.

[Client release](https://github.com/tus/tus-js-client/releases/tag/v4.3.1) · [Protocol](https://tus.io/protocols/resumable-upload) · [Public client advisories](https://github.com/tus/tus-js-client/security/advisories)
