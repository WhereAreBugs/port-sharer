include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI for Port Sharer
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+port-sharer
PKG_LICENSE:=MIT

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot build rules
$(eval $(call BuildPackage,luci-app-port-sharer))
