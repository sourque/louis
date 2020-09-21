package correlate

import (
    "os"

    "syscall"
)

func Owner(pathName string) (uint32, error) {
    file, err := os.Stat(pathName)
    if err != nil {
        return 0, err
    }
    return file.Sys().(*syscall.Stat_t).Uid, nil
}
