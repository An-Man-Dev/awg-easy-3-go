package main

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Offline recovery does not depend on DNS or the public panel. The store lock
// requires stopping the daemon first; only a local filesystem owner can use it.
func setAddresses(input io.Reader, dir string) error {
	var next model.Addresses
	decoder := json.NewDecoder(io.LimitReader(input, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&next); err != nil {
		return fmt.Errorf("invalid address JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("only one JSON object is allowed")
	}
	next.Revision = 1
	if err := next.Validate(); err != nil {
		return err
	}
	next.PanelOrigin, _ = config.PublicOrigin(next.PanelOrigin)
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	state, err := st.Load()
	if err != nil {
		return err
	}
	next.Revision = state.Addresses.Revision + 1
	if err = st.SaveAddresses(next, state.Addresses.Revision); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Addresses saved. Start the panel to apply network rules and allowed origins.")
	return nil
}
