// SPDX-License-Identifier: AGPL-3.0-only

package config

import "path/filepath"

func (sCfg *Server) ownKeyPath(file, def string) string {
	if file == "" {
		file = def
	}
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(sCfg.DataDir, file)
}

func (sCfg *Server) IdentityPrivateKeyPath() string {
	return sCfg.ownKeyPath(sCfg.IdentityPrivateKeyFile, "identity.private.pem")
}

func (sCfg *Server) IdentityPublicKeyPath() string {
	return sCfg.ownKeyPath(sCfg.IdentityPublicKeyFile, "identity.public.pem")
}

func (sCfg *Server) LinkPrivateKeyPath() string {
	return sCfg.ownKeyPath(sCfg.LinkPrivateKeyFile, "link.private.pem")
}

func (sCfg *Server) LinkPublicKeyPath() string {
	return sCfg.ownKeyPath(sCfg.LinkPublicKeyFile, "link.public.pem")
}
