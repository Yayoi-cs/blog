# linux on ASUS expert book ultra

OS: Cachy OS

Cachy OS supports linux 7.x

## Touchpad

```bash
sudo install -d -m 0755 /etc/libinput

sudo tee /etc/libinput/local-overrides.quirks >/dev/null <<'EOF'
[ASUS ExpertBook Ultra B9406 Touchpad]
MatchUdevType=touchpad
MatchBus=i2c
MatchVendor=0x093A
MatchProduct=0x4F05
MatchDMIModalias=dmi:*svnASUS*:pn*B9406*
AttrEventCode=-ABS_MT_PRESSURE;-ABS_PRESSURE;
EOF
```

then reboot

## Brightness
append `xe.enable_dpcd_backlight=2` to your limine config
```plain text
cat /etc/default/limine
ESP_PATH="/boot"
KERNEL_CMDLINE[default]+="quiet nowatchdog splash rw rootflags=subvol=/@ root=UUID=<REDACTED> xe.enable_dpcd_backlight=2"
BOOT_ORDER="*, *lts, *fallback, Snapshots"
```
apply cmdline
```Bash
sudo limine-mkinitcpio
```
then reboot

## Audio

See `cat /proc/asound/cards` you will confirm:
```plain text
--- no soundcards ---
```

### patch to your kernel

```bash
git clone https://github.com/CachyOS/linux-cachyos.git
cd linux-cachyos/linux-cachyos
```
fix prefix
```bash
sed -i '/^pkgbase="linux-\$_pkgsuffix"$/i _pkgsuffix=cachyos-soundpatch' PKGBUILD
```
extract source code
```bash
makepkg -os
```

Then see `drivers/soundwire/dmi-quirks.c`.
You will confirm
```C
{
        .matches = {
                DMI_MATCH(DMI_SYS_VENDOR, "ASUS"),
                DMI_MATCH(DMI_BOARD_NAME, "UX5406AA"),
        },
        .driver_data = (void *)ghost_realtek,
},
```
Append patched data next to the code
```c
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "ASUS"),
			DMI_MATCH(DMI_BOARD_NAME, "B9406CAA"),
		},
		.driver_data = (void *)ghost_realtek,
	},
```

You will see the diff like:

```bash
[becky@chang linux-cachyos]$ diff -u \   
    "$SRC/drivers/soundwire/dmi-quirks.c.orig" \
    "$SRC/drivers/soundwire/dmi-quirks.c"
--- /home/becky/app/linux-cachyos/linux-cachyos/src/cachyos-7.2.0-1/drivers/soundwire/dmi-quirks.c.orig 2026-08-26 15:28:13.575882895 +0900
+++ /home/becky/app/linux-cachyos/linux-cachyos/src/cachyos-7.2.0-1/drivers/soundwire/dmi-quirks.c      2026-08-26 15:28:55.024220995 +0900
@@ -187,6 +187,13 @@
        },
        {
                .matches = {
+                       DMI_MATCH(DMI_SYS_VENDOR, "ASUS"),
+                       DMI_MATCH(DMI_BOARD_NAME, "B9406CAA"),
+               },
+               .driver_data = (void *)ghost_realtek,
+       },
+       {
+               .matches = {
                        DMI_MATCH(DMI_SYS_VENDOR, "LENOVO"),
                        DMI_MATCH(DMI_PRODUCT_NAME, "83QK"),
                },
```

then build patched kernel
```bash
makepkg -esi
```

after reboot, exec `amixer -c 0 sset 'Speaker' on` to turn on the speaker

### GPU
You can use xpu with

### Japanese
英語書いてgoogle translateに翻訳してもらいな
