include $(TOPDIR)/rules.mk

PKG_NAME:=trafficmon
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/trafficmon
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Traffic Monitoring Tool (Rust)
  DEPENDS:=+libpcap +libstdcpp
endef

define Package/trafficmon/description
  A traffic monitoring tool written in Rust for OpenWrt.
endef

define Package/trafficmon/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/trafficmon $(1)/usr/bin/
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/trafficmon $(1)/etc/init.d/
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/trafficmon $(1)/etc/config/trafficmon
endef

$(eval $(call BuildPackage,trafficmon))