package main

import (
	"fmt"

	"github.com/linxGnu/grocksdb"
)

func main() {

	bbto := grocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetBlockCache(grocksdb.NewLRUCache(3 << 30))

	opts := grocksdb.NewDefaultOptions()
	opts.SetBlockBasedTableFactory(bbto)
	opts.SetCreateIfMissing(true)

	db, err := grocksdb.OpenDb(opts, "1.db")
	if err != nil {
		panic(err)
	}

	//ro := grocksdb.NewDefaultReadOptions()
	wo := grocksdb.NewDefaultWriteOptions()

	fmt.Println("before db put")

	err = db.Put(wo, []byte("foo"), []byte("bar"))
	if err != nil {
		panic(err)
	}

	fmt.Println("after db put")

	db.Close()
}
