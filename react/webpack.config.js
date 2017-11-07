 var path = require('path');
 var webpack = require('webpack');
 module.exports = {
     entry: './index.js',
     output: {
         path: path.resolve(__dirname, 'build'),
         filename: 'index.bundle.js'
     },
     module: {
         loaders: [
             {
                 test: /\.js$/,
                 exclude: /node_modules/,
                 loader: 'babel-loader',
                 query: {
                     presets: ['react', 'es2015']
                 }
             },
             {
                test: /\.css$/,  
                // include: /styles/,  
                loaders: ['style-loader', 'css-loader'],
            },
            {
                test: /\.png$/,
                loader: "url-loader",
                query: { mimetype: "image/png" }
            },
            {
              test: /\.(woff|woff2)?$/,
              loader: 'url-loader',
              options: {
                limit: 50000,
                mimetype: 'application/font-woff',
              },
            },
         ]
     },
     stats: {
         colors: true
     }
     //devtool: 'source-map'
 };
