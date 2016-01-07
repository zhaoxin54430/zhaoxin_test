#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libshmem
PKG_VERSION:=1.0
#PKG_RELEASE:=4

PKG_LICENSE:=LGPL-2.1
PKG_MAINTAINER:=Felix Fietkau <nbd@openwrt.org>

include $(INCLUDE_DIR)/package.mk

define Package/libshmem
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=share memory library
endef

define Package/libshmem/description
 share memory library
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		all
endef

define Build/InstallDev
#	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig $(1)/usr/include/libnl-tiny
#	$(CP) $(PKG_BUILD_DIR)/libshmem.h $(1)/usr/include/
#	$(CP) $(PKG_BUILD_DIR)/libnl-tiny.so $(1)/usr/lib/
#	$(CP) ./files/libnl-tiny.pc $(1)/usr/lib/pkgconfig
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libshmem.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libshmem.h $(1)/usr/include/
endef

define Package/libshmem/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libshmem.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libshmem))
