package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kdomanski/iso9660"
	"github.com/nwaples/rardecode/v2"
)

// Stream opens an archive and calls processFile for each file inside it.
// It does NOT extract files to disk. The reader is valid only for the duration of the callback.
func Stream(archivePath, password string, processFile func(name string, size int64, reader io.Reader) error) error {
	ext := strings.ToLower(filepath.Ext(archivePath))

	if ext == ".zip" {
		return streamZip(archivePath, processFile)
	} else if ext == ".gz" && strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz") {
		return streamTarGz(archivePath, processFile)
	} else if ext == ".tar" {
		return streamTar(archivePath, processFile)
	} else if ext == ".rar" {
		return streamRar(archivePath, password, processFile)
	} else if ext == ".iso" {
		return streamIso(archivePath, processFile)
	}

	return fmt.Errorf("unsupported archive format: %s", ext)
}

func streamZip(archivePath string, processFile func(name string, size int64, reader io.Reader) error) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return err
		}

		err = processFile(file.Name, file.FileInfo().Size(), rc)
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func streamRar(archivePath, password string, processFile func(name string, size int64, reader io.Reader) error) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var opts []rardecode.Option
	if password != "" {
		opts = append(opts, rardecode.Password(password))
	}

	rr, err := rardecode.NewReader(file, opts...)
	if err != nil {
		return err
	}

	for {
		header, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.IsDir {
			continue
		}

		err = processFile(header.Name, header.UnPackedSize, rr)
		if err != nil {
			return err
		}
	}

	return nil
}

func streamTarGz(archivePath string, processFile func(name string, size int64, reader io.Reader) error) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	return extractTarStream(tar.NewReader(gzr), processFile)
}

func streamTar(archivePath string, processFile func(name string, size int64, reader io.Reader) error) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return extractTarStream(tar.NewReader(file), processFile)
}

func extractTarStream(tr *tar.Reader, processFile func(name string, size int64, reader io.Reader) error) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		err = processFile(header.Name, header.Size, tr)
		if err != nil {
			return err
		}
	}
	return nil
}

func streamIso(archivePath string, processFile func(name string, size int64, reader io.Reader) error) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	img, err := iso9660.OpenImage(file)
	if err != nil {
		return err
	}

	root, err := img.RootDir()
	if err != nil {
		return err
	}

	return walkIso(root, "", processFile)
}

func walkIso(dir *iso9660.File, prefix string, processFile func(name string, size int64, reader io.Reader) error) error {
	children, err := dir.GetChildren()
	if err != nil {
		return err
	}

	for _, c := range children {
		name := c.Name()
		// Skip special entries
		if name == "." || name == ".." || name == "" {
			continue
		}

		path := prefix + name
		if c.IsDir() {
			if err := walkIso(c, path+"/", processFile); err != nil {
				return err
			}
		} else {
			if err := processFile(path, c.Size(), c.Reader()); err != nil {
				return err
			}
		}
	}
	return nil
}
