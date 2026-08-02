# Maintainer: Default profile <htovver@gmail.com>
pkgname=post2mpv-server-git
pkgver=1.0.0.r0.g0000000
pkgrel=1
pkgdesc="HTTP server for mpv/peerflix/yt-dlp control"
arch=('x86_64')
url="https://github.com/netnomadd/post2mpv-server"
license=('MIT')
depends=('mpv')
optdepends=(
    'yt-dlp: for download action'
    'peerflix: for torrent playback'
    'vot-cli-live: for translate action'
)
makedepends=('go' 'git')
install="post2mpv-server.install"
source=("$pkgname::git+$url.git")
sha256sums=('SKIP')

pkgver() {
    cd "$pkgname"
    local tag count hash
    if tag=$(git describe --tags --abbrev=0 2>/dev/null); then
        count=$(git rev-list --count "${tag}..HEAD")
        hash=$(git rev-parse --short HEAD)
        printf '%s.r%s.g%s' "${tag#v}" "$count" "$hash"
    else
        printf 'r%s.g%s' "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
    fi
}

build() {
    cd "$pkgname"
    export CGO_ENABLED=0
    go build -trimpath -ldflags="-s -w" -o post2mpv .
}

package() {
    cd "$pkgname"

    install -Dm755 post2mpv         "$pkgdir/usr/bin/post2mpv"
    install -Dm755 vot              "$pkgdir/usr/bin/vot"
    install -Dm644 post2mpv.service "$pkgdir/usr/lib/systemd/user/post2mpv.service"
}
