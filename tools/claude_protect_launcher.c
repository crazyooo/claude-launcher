/* Native pre-Python trust gate. Links only macOS system libraries.
 * No xcode-select shim, user environment, or user-supplied runtime paths.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <fts.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PROTECT_ROOT
#define PROTECT_ROOT "/Library/PrivilegedHelperTools/local.crazyooo.claude-protect"
#endif
#ifndef PYTHON_FRAMEWORK
#define PYTHON_FRAMEWORK "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework"
#endif

static int blocked(const char *reason) {
    fprintf(stderr, "Claude protect: %s; administrator repair required.\n", reason);
    return 78;
}
static int inside(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '/' || path[n] == '\0');
}
static int trusted_node(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid != 0 || S_ISLNK(st.st_mode) ||
        (st.st_mode & 0022) || !(S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))) return 0;
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT; /* macOS: no extended ACL attribute. */
    acl_entry_t entry;
    int count = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    acl_free(acl);
    return count != 0; /* No extended ACL entries are allowed. */
}
static int trusted_chain(const char *path) {
    char buffer[PATH_MAX];
    if (path[0] != '/' || strlen(path) >= sizeof(buffer)) return 0;
    strcpy(buffer, path);
    if (!trusted_node("/")) return 0;
    for (char *p = buffer + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            int ok = trusted_node(buffer);
            *p = '/';
            if (!ok) return 0;
        }
    }
    return trusted_node(buffer);
}
static int trusted_tree(const char *root) {
    if (!trusted_chain(root)) return 0;
    char *paths[] = {(char *)root, NULL};
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (!tree) return 0;
    int ok = 1;
    FTSENT *item;
    errno = 0;
    while ((item = fts_read(tree))) {
        if (item->fts_info == FTS_DP) { errno = 0; continue; }
        if (item->fts_info == FTS_SL) {
            char target[PATH_MAX];
            /* Framework aliases may only resolve within the already scanned tree. */
            if (!item->fts_statp || item->fts_statp->st_uid != 0 ||
                !realpath(item->fts_path, target) || !inside(target, root) ||
                !trusted_chain(target)) { ok = 0; break; }
        } else if (item->fts_info == FTS_D || item->fts_info == FTS_F) {
            if (!trusted_node(item->fts_path)) { fprintf(stderr, "Untrusted runtime item: %s\n", item->fts_path); ok = 0; break; }
        } else { fprintf(stderr, "Unsupported runtime item: %s (%d)\n", item->fts_path, item->fts_info); ok = 0; break; }
        errno = 0;
    }
    if (!item && errno != 0) ok = 0;
    fts_close(tree);
    return ok;
}
int main(int argc, char **argv) {
    /* Validate before Python can import even a single standard-library module. */
    if (!trusted_tree(PYTHON_FRAMEWORK)) return blocked("untrusted_python_runtime");
    char python[PATH_MAX];
    if (!realpath(PYTHON_FRAMEWORK "/Versions/Current/bin/python3", python) ||
        !inside(python, PYTHON_FRAMEWORK)) return blocked("invalid_python_executable");
    if (argc == 2 && strcmp(argv[1], "--check-runtime") == 0) return 0;
    if (!trusted_chain(PROTECT_ROOT "/current-release")) return blocked("untrusted_release_pointer");
    FILE *file = fopen(PROTECT_ROOT "/current-release", "r");
    if (!file) return blocked("missing_release_pointer");
    char release[42] = {0};
    size_t n = fread(release, 1, sizeof(release), file);
    fclose(file);
    if (n != 40 || strncmp(release, "release-", 8) != 0) return blocked("invalid_release_pointer");
    for (size_t i = 8; i < 40; i++)
        if (!((release[i] >= '0' && release[i] <= '9') || (release[i] >= 'a' && release[i] <= 'f')))
            return blocked("invalid_release_pointer");
    char directory[PATH_MAX], script[PATH_MAX];
    snprintf(directory, sizeof(directory), "%s/%s", PROTECT_ROOT, release);
    if (!trusted_tree(directory)) return blocked("untrusted_protect_code");
    snprintf(script, sizeof(script), "%s/claude_protect_privileged.py", directory);
    char **args = calloc((size_t)argc + 5, sizeof(char *));
    if (!args) return blocked("out_of_memory");
    args[0] = python; args[1] = "-I"; args[2] = "-S"; args[3] = "-B"; args[4] = script;
    for (int i = 1; i < argc; i++) args[i + 4] = argv[i];
    char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "HOME=/var/root", NULL};
    execve(python, args, env);
    return blocked("python_exec_failed");
}
