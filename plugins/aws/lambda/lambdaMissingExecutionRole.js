var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Functions Overview with Assigned Roles',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'High',
    description: 'List all AWS Lambda functions and verify that their assigned IAM roles exist.',
    more_info: 'This plugin uses Lambda:listFunctions, Lambda:getFunction, IAM:listRoles, and IAM:getRole to fetch Lambda and IAM details.',
    recommended_action: 'Ensure all Lambda functions have valid IAM roles assigned.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunction', 'IAM:listRoles', 'IAM:getRole'],
    realtime_triggers: [
        'lambda:CreateFunction',
        'lambda:UpdateFunctionConfiguration',
        'lambda:DeleteFunction',
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb) {

            // Fetch Lambda functions
            var listFunctions = helpers.addSource(cache, source, ['lambda', 'listFunctions', region]);
            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3, `Unable to query Lambda functions: ${helpers.addError(listFunctions)}`, region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found. Pass.', region);
                return rcb();
            }

            // Fetch IAM roles once per region
            var listRoles = helpers.addSource(cache, source, ['iam', 'listRoles', region]);
            if (!listRoles || listRoles.err || !listRoles.data || !listRoles.data.length) {
                // If IAM roles cannot be fetched, fail
                helpers.addResult(results, 3, `Unable to query IAM roles: ${helpers.addError(listRoles)}`, region);
                return rcb();
            }

            async.each(listFunctions.data, function(lambdaFunction, cb) {
                if (!lambdaFunction.FunctionName) return cb();

                // Get function details
                var getFunction = helpers.addSource(cache, source, ['lambda', 'getFunction', region, lambdaFunction.FunctionName]);
                if (!getFunction || getFunction.err || !getFunction.data || !getFunction.data.Configuration) {
                    helpers.addResult(results, 3,
                        `Unable to get Lambda function details: ${helpers.addError(getFunction)}`,
                        region, lambdaFunction.FunctionArn
                    );
                    return cb();
                }

                var lambdaConfig = getFunction.data.Configuration;


                // Get Lambda's assigned IAM role ARN
                var assignedRoleArn = lambdaConfig.Role || null;

                if (!assignedRoleArn) {
                    // No role assigned = fail
                    helpers.addResult(results, 3,
                        `Lambda function "${lambdaFunction.FunctionName}" has NO assigned IAM role!`,
                        region, lambdaFunction.FunctionArn
                    );
                    return cb();
                }

                // Check if assigned role exists in IAM roles list
                var roleObj = listRoles.data.find(r => assignedRoleArn.endsWith(r.RoleName));

                if (roleObj) {
                    // Role exists, optional: get role details
                    var getRole = helpers.addSource(cache, source, ['iam', 'getRole', region, roleObj.RoleName]);

                    if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                        helpers.addResult(results, 2,
                            `Assigned IAM role exists but unable to fetch details: ${assignedRoleArn}`,
                            region, lambdaFunction.FunctionArn
                        );
                    } else {
                        helpers.addResult(results, 0,
                            `Assigned IAM role exists and retrieved: ${assignedRoleArn}`,
                            region, lambdaFunction.FunctionArn
                        );
                    }
                } else {
                    
                    helpers.addResult(results, 2,
                        `Assigned IAM role NOT found: ${assignedRoleArn}`,
                        region, lambdaFunction.FunctionArn
                    );
                }

                cb();
            }, function() {
                rcb();
            });

        }, function() {
            callback(null, results, source);
        });
    }
};
