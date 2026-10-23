/* Benign PKCS#11 loader probe for isolated CI only.
 * If dlopen reaches this fixture, record a marker. Never export PKCS#11 API.
 * This tests whether an agent attempts any provider load, not exploitability.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void probe_provider_loaded(void) {
    const char *path = getenv("TREE_AGENT_PROBE_MARKER");
    if (path && *path) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            const char message[] = "provider-loaded\n";
            (void)write(fd, message, sizeof(message) - 1);
            (void)close(fd);
        }
    }
}
