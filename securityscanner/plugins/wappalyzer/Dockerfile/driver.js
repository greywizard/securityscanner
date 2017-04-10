(function() {
	var
		url,
		originalUrl,
		scriptDir,
		scriptPath      = require('fs').absolute(require('system').args[0]),
		resourceTimeout = 9000,
		args            = [],
		debug           = false;

	try {
		// Working directory
		scriptDir = scriptPath.split('/'); scriptDir.pop(); scriptDir = scriptDir.join('/');

		require('fs').changeWorkingDirectory(scriptDir);

		require('system').args.forEach(function(arg) {
			switch ( arg ) {
				case '-v':
				case '--verbose':
					debug = true;

					break;
				case '--resource-timeout':
					resourceTimeout = arg;
					break;
				default:
					url = originalUrl = arg;
			}
		});

		if ( !url ) {
			throw new Error('Usage: phantomjs ' + require('system').args[0] + ' <url>');
		}

		if ( !phantom.injectJs('wappalyzer.js') ) {
			throw new Error('Unable to open file js/wappalyzer.js');
		}

		wappalyzer.driver = {
			/**
			 * Log messages to console
			 */
			log: function(args) {
				if ( debug || args.type !== 'debug' ) {
					console.log(args.message);
				}
			},

			/**
			 * Display apps
			 */
			displayApps: function() {
				var
					app, cats,
					apps  = [],
					count = wappalyzer.detected[url] ? Object.keys(wappalyzer.detected[url]).length : 0;

				wappalyzer.log('driver.displayApps');

				if ( count ) {
					for ( app in wappalyzer.detected[url] ) {
						cats = [];
						icon = wappalyzer.apps[app].icon;

						wappalyzer.apps[app].cats.forEach(function(cat) {
							cats.push(wappalyzer.categories[cat]);
						});

						apps.push({
							name: app,
							confidence:  wappalyzer.detected[url][app].confidenceTotal,
							version:     wappalyzer.detected[url][app].version,
							icon:	     icon,	
							categories:  cats
						});
					}
				}
                console.log(JSON.stringify({ applications: apps }));
			},

			/**
			 * Initialize
			 */
			init: function() {
				var
					page, hostname,
					headers = {};
					a       = document.createElement('a'),
					json    = JSON.parse(require('fs').read('apps.json'));

				wappalyzer.log('driver.init');

				a.href = url.replace(/#.*$/, '');

				hostname = a.hostname;

				wappalyzer.apps       = json.apps;
				wappalyzer.categories = json.categories;

				page = require('webpage').create();

				page.settings.loadImages      = false;
				page.settings.userAgent       = 'Mozilla/5.0 (compatibile; GreyWizard/2; +https://greywizard.com/en)';
				page.settings.resourceTimeout = resourceTimeout;

				page.onConsoleMessage = function(message) {
					wappalyzer.log(message);
				};

				page.onError = function(message) {
					wappalyzer.log(message);

					//console.log(JSON.stringify({ applications: [] }));

					//phantom.exit(1);
				};

				page.onResourceTimeout = function() {
					wappalyzer.log('Resource timeout');

					console.log(JSON.stringify({ applications: [] }));

					phantom.exit(1);
				};

				page.onResourceReceived = function(response) {
					if ( response.url.replace(/\/$/, '').toLowerCase() === url.replace(/\/$/, '').toLowerCase() ) {
						if ( response.redirectURL ) {
							url = response.redirectURL;

							return;
						}

						if ( response.stage === 'end' && response.status === 200 && response.contentType.indexOf('text/html') !== -1 ) {
							response.headers.forEach(function(header) {
								headers[header.name.toLowerCase()] = header.value;
							});
						}
					}
				};
                
                page.onResourceError = function(resourceError) {
                    wappalyzer.log(resourceError.url + ': ' + resourceError.errorString);
                };
                
             	page.open(url, function(status) {
					var html, environmentVars;
					if ( status === 'success' || page.content) { //page.content solves issue: https://github.com/ariya/phantomjs/issues/12750
                        html = page.content;

						// Collect environment variables
						environmentVars = page.evaluate(function() {
							var i, environmentVars;

							for ( i in window ) {
								environmentVars += i + ' ';
							}

							return environmentVars;
						});

						wappalyzer.log({ message: 'environmentVars: ' + environmentVars });

						environmentVars = environmentVars.split(' ').slice(0, 500);

						wappalyzer.analyze(hostname, url, {
							html:    html,
							headers: headers,
							env:     environmentVars
						});

						phantom.exit(0);
					} else {
						wappalyzer.log('Failed to fetch page');

						console.log(JSON.stringify({ applications: [] }));

						phantom.exit(1);
					}
				});
			}
		};

		wappalyzer.init();
	} catch ( e ) {
		wappalyzer.log(e);

		console.log(JSON.stringify({ applications: [] }));

		phantom.exit(1);
	}
})();
