# Deliberately contains no Java, no JVM flags, and no JAVA_OPTS-style var.
# The only thing it has in common with a Java image is the FILENAME, which is
# precisely what the pre-fix tool was keying off.
FROM nginx:1.27.0-alpine
COPY site/ /usr/share/nginx/html/
USER 101
