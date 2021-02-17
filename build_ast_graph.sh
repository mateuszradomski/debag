#/bin/sh

./build.sh && ./debag -wl && dot -Tpng graph_src.dot > graph.png && xdg-open graph.png
