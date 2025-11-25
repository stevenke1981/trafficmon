include $(TOPDIR)/rules.mk

PKG_NAME:=trafficmon
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Steven Ke <stevenke1981@gmail.com>
PKG_LICENSE:=MIT

CARGO_PKG_NAME:=trafficmon
CARGO_PKG_SOURCE:=src
CARGO_PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cargo.mk

define Package/trafficmon
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Traffic Monitor with nftables only
  DEPENDS:=+libpcap +nftables
  URL:=https://github.com/stevenke1981/trafficmon
endef

define Package/trafficmon/description
  A traffic monitoring tool for OpenWrt that uses nftables for traffic classification and filtering.
endef

define Package/trafficmon/conffiles
/etc/config/trafficmon
endef

define Build/Prepare
	$(Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/trafficmon/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARGS)/release/trafficmon $(1)/usr/bin/
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./config/trafficmon.conf $(1)/etc/config/trafficmon
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/trafficmon.init $(1)/etc/init.d/trafficmon
endef

$(eval $(call BuildPackage,trafficmon))