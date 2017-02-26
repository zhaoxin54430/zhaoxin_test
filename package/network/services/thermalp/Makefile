#
# Copyright (C) 2010-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=thermalp
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/thermalp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=thermalp
  DEPENDS:=+libcurl +libjson-c +libubox +libuci
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/thermalp/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/thermalp $(1)/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/thermalp.sh $(1)/etc/init.d/thermalp
#	$(INSTALL_BIN) ./files/check_res.sh $(1)/bin/
#	$(INSTALL_BIN) ./files/res_check_size.sh $(1)/bin/
endef

$(eval $(call BuildPackage,thermalp))
