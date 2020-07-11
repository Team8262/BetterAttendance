#!/usr/bin/env bash

jq -c '.lastRow = 2' data.json > tmp.$$.json && mv tmp.$$.json data.json