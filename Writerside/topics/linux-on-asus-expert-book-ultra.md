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
You can use xpu

i.e.,
```py

import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms
from torch.utils.data import DataLoader

import matplotlib.pyplot as plt
from tqdm import tqdm


class SimpleCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv_stack = nn.Sequential(
            nn.Conv2d(1, 8, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(8, 16, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
        )
        self.fc_stack = nn.Sequential(
            nn.Flatten(),
            nn.Linear(16 * 7 * 7, 64),
            nn.ReLU(),
            nn.Linear(64, 10),
        )

    def forward(self, x):
        return self.fc_stack(self.conv_stack(x))


assert(torch.xpu.is_available())
device = torch.device("xpu")
transform = transforms.ToTensor()

train_data = datasets.MNIST(root="./data", train=True,  download=True, transform=transform)
test_data  = datasets.MNIST(root="./data", train=False, download=True, transform=transform)

train_loader = DataLoader(train_data, batch_size=2**8, shuffle=True)
test_loader  = DataLoader(test_data,  batch_size=2**8, shuffle=False)

model = SimpleCNN().to(device)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3)

EPOCHS = 100
for epoch in range(EPOCHS):
    model.train()
    for images, labels in tqdm(train_loader, desc=f"Epoch {epoch+1}/{EPOCHS}"):
        images, labels = images.to(device), labels.to(device)
        optimizer.zero_grad()
        loss = criterion(model(images), labels)
        loss.backward()
        optimizer.step()

model.eval()
correct = total = 0
with torch.no_grad():
    for images, labels in test_loader:
        images, labels = images.to(device), labels.to(device)
        preds = model(images).argmax(dim=1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)
print(f"Inference accuracy: {correct/total:.4f}")

```
