#!/bin/bash

# Script to fix metrics issues in user-service/main.go

echo "Commenting out metricsMiddleware function and usage..."

# Comment out the metricsMiddleware function definition
sed -i 's/^func metricsMiddleware()/\/\/ func metricsMiddleware()/' user-service/main.go

# Comment out the app.Use(metricsMiddleware()) line  
sed -i 's/app\.Use(metricsMiddleware())/\/\/ app.Use(metricsMiddleware())/' user-service/main.go

# Comment out any other metricsMiddleware references
sed -i 's/metricsMiddleware/\/\/ metricsMiddleware/g' user-service/main.go

echo "Checking for remaining metricsMiddleware references..."
grep -n "metricsMiddleware" user-service/main.go || echo "No remaining references found"

echo "Done!"
