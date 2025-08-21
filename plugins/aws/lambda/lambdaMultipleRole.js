var async = require('async');
var helpers = require('../../../helpers/aws');


module.exports = {
    title: 'Lambda Function can share Multiple Roles',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Identify AWS Lambda functions that share the same IAM execution role and verify if the roles exist.',
    more_info: 'This plugin uses Lambda:listFunctions, Lambda:getFunction, and IAM:getRole to fetch Lambda and IAM details.',
    recommended_action: 'Ensure that each Lambda function has its own IAM role assigned and roles are not shared.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunction', 'IAM:getRole'],
    realtime_triggers: [
        'lambda:CreateFunction',
        'lambda:UpdateFunctionConfiguration',
        'lambda:DeleteFunction',
    ],
    remediation_description:"This remediation creates a unique IAM role for the Lambda function and attaches the required policies before updating the function configuration",
    remediation_min_version:"202508210226",
    actions:{
        remediate: [
        'iam:createRole',
        'iam:attachRolePolicy',
        'lambda:updateFunctionConfiguration'
    ],
    rollback: [
        'lambda:updateFunctionConfiguration',
        'iam:detachRolePolicy',
        'iam:deleteRole'
    ]
},
permissions: {
    remediate: [
        'iam:CreateRole',
        'iam:AttachRolePolicy',
        'lambda:UpdateFunctionConfiguration'
    ],
    rollback: [
        'lambda:UpdateFunctionConfiguration',
        'iam:DetachRolePolicy',
        'iam:DeleteRole'
    ]
},
remediation_inputs: {
    roleName: {
        name: '(Mandatory) New Role Name',
        description: 'The IAM Role name that will be created for the Lambda function.',
        regex: '^[A-Za-z0-9+=,.@_-]{1,64}$',
        required: true
    },
    policyArn: {
        name: '(Mandatory) IAM Policy ARN',
        description: 'The IAM policy ARN to attach to the new role (e.g., AWSLambdaBasicExecutionRole).',
        regex: '^arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_-]+$',
        required: true
    },
    lambdaFunctionName: {
        name: '(Mandatory) Lambda Function Name',
        description: 'The Lambda function that will be updated to use the new IAM role.',
        regex: '^[a-zA-Z0-9-_]{1,64}$',
        required: true
    }
},

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb) {

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

            var roleToFunctions = {};

            async.each(listFunctions.data, function(lambdaFunction, cb) {
                if (!lambdaFunction.FunctionName) return cb();

                var getFunction = helpers.addSource(cache, source, ['lambda', 'getFunction', region, lambdaFunction.FunctionName]);
                if (!getFunction || getFunction.err || !getFunction.data || !getFunction.data.Configuration) {
                    helpers.addResult(results, 3,
                        `Unable to get Lambda function details: ${helpers.addError(getFunction)}`,
                        region, lambdaFunction.FunctionArn
                    );
                    return cb();
                }

                var lambdaConfig = getFunction.data.Configuration;
                var assignedRoleArn = lambdaConfig.Role || null;

                if (!assignedRoleArn) {
                    helpers.addResult(results, 3,
                        `Lambda function "${lambdaFunction.FunctionName}" has NO assigned IAM role!`,
                        region, lambdaFunction.FunctionArn
                    );
                    return cb();
                }

                if (!roleToFunctions[assignedRoleArn]) {
                    roleToFunctions[assignedRoleArn] = [];
                }
                roleToFunctions[assignedRoleArn].push(lambdaFunction.FunctionName);

                
                var getRole = helpers.addSource(cache, source, ['iam', 'getRole', region, assignedRoleArn]);

                if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                    helpers.addResult(results, 2,
                        `Assigned IAM role not found or inaccessible: ${assignedRoleArn}`,
                        region, lambdaFunction.FunctionArn
                    );
                }
                cb();
            }, function() {
                for (var roleArn in roleToFunctions) {
                    if (roleToFunctions.hasOwnProperty(roleArn)) {
                        var functionsUsingRole = roleToFunctions[roleArn];
                        if (functionsUsingRole.length > 1) {
                            helpers.addResult(results, 2,
                                `IAM role "${roleArn}" is shared by multiple Lambda functions: ${functionsUsingRole.join(', ')}`,
                                region
                            );
                        } else {
                            helpers.addResult(results, 0,
                                `IAM role "${roleArn}" is uniquely assigned to Lambda function "${functionsUsingRole[0]}"`,
                                region
                            );
                        }
                    }
                }
                rcb();
            });

        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
    var putCall = this.actions.remediate;
    var pluginName = 'lambdaUniqueRole';
    var functionName = resource.split(':').pop().split('/').pop();
    var region = helpers.defaultRegion(settings);

    
    var getFunction = helpers.addSource(cache, {},
        ['lambda', 'getFunction', region, functionName]);

    if (!getFunction || getFunction.err || !getFunction.data || !getFunction.data.Configuration) {
        return callback('Unable to get Lambda function details', null);
    }

    var lambdaConfig = getFunction.data.Configuration;
    var oldRoleArn = lambdaConfig.Role;

   
    var newRoleName = `${functionName}-execution-role`;
    var trustPolicy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "lambda.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }]
    };

    var createRoleParams = {
        RoleName: newRoleName,
        AssumeRolePolicyDocument: JSON.stringify(trustPolicy)
    };

    var createRole = helpers.addSource(cache, {},
        ['iam', 'createRole', region, createRoleParams]);

    if (!createRole || createRole.err || !createRole.data || !createRole.data.Role) {
        return callback('Unable to create IAM role for Lambda', null);
    }

    var newRoleArn = createRole.data.Role.Arn;

    
    var basicPolicy = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole';
    helpers.addSource(cache, {}, ['iam', 'attachRolePolicy', region, newRoleName, basicPolicy]);

    
    var updateParams = {
        FunctionName: functionName,
        Role: newRoleArn
    };

    config.region = region;

    var remediation_file = settings.remediation_file;
    remediation_file['pre_remediate']['actions'][pluginName][resource] = {
        'OldRole': oldRoleArn
    };

    helpers.remediatePlugin(config, putCall[0], updateParams, function(err) {
        if (err) {
            remediation_file['remediate']['actions'][pluginName]['error'] = err;
            return callback(err, null);
        }

        let action = updateParams;
        action.action = putCall;

        remediation_file['post_remediate']['actions'][pluginName][resource] = {
            'NewRole': newRoleArn,
            'AttachedPolicy': basicPolicy
        };
        remediation_file['remediate']['actions'][pluginName][resource] = {
            'Action': 'UniqueExecutionRole',
            'Lambda': functionName
        };

        settings.remediation_file = remediation_file;
        return callback(null, action);
    });
},
    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }

    
};
