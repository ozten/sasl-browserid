SASL_SRC=/home/vagrant/cyrus-sasl-2.1.23
SASL_BUILD=/home/vagrant/local/sasl2/lib/sasl2

echo "Building with ${SASL_SRC} and ${SASL_BUILD}"
cd plugins
mkdir -p .deps
mkdir -p .libs

gcc -DHAVE_CONFIG_H -I${SASL_SRC} -I${SASL_SRC}/plugins -I${SASL_SRC}/include -I${SASL_SRC}/lib -I${SASL_SRC}/sasldb -Wall -W -g -O2 -MT browserid.lo -MD -MP -MF .deps/browserid.Tpo -c browserid.c  -fPIC -DPIC -o browserid.lo
gcc -DHAVE_CONFIG_H -I${SASL_SRC} -I${SASL_SRC}/plugins -I${SASL_SRC}/include -I${SASL_SRC}/lib -I${SASL_SRC}/sasldb -Wall -W -g -O2 -MT browserid_init.lo -MD -MP -MF .deps/browserid_init.Tpo -c browserid_init.c  -fPIC -DPIC -o browserid_init.lo

pwd

/bin/bash ${SASL_SRC}/libtool --mode=link gcc  -Wall -W -g -O2 -module -export-dynamic -rpath ${SASL_BUILD}  -o libbrowserid.la  -version-info 2:23:0 browserid.lo browserid_init.lo ${SASL_SRC}/plugins/plugin_common.lo  -lresolv -lresolv  -lcurl -lyajl

#rm -fr .libs/libbrowserid.la .libs/libbrowserid.* .libs/libbrowserid.*
#gcc -shared  browserid.lo browserid_init.lo ${SASL_SRC}/plugins/plugin_common.lo  -lresolv -lresolv -lcurl -lyajl -lc  -Wl,-soname -Wl,libbrowserid.so.2 -o .libs/libbrowserid.so.2.0.23
#(cd .libs && rm -f libbrowserid.so.2 && ln -s libbrowserid.so.2.0.23 libbrowserid.so.2)
#(cd .libs && rm -f libbrowserid.so && ln -s libbrowserid.so.2.0.23 libbrowserid.so)
#(cd .libs && rm -f libbrowserid.la && ln -s ../libbrowserid.la libbrowserid.la)
sudo cp libbrowserid.la .libs/libbrowserid.so* /usr/lib/sasl2/
sudo ~/local/sasl2/sbin/pluginviewer -p /usr/lib/sasl2/
cd ../