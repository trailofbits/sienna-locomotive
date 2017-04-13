/*
** TODO:
**      
*/

/*
** GLOBAL
*/

window.ui_data = {}

/*
** SYSTEM
*/

function systemList(empty_list=false) {
    $.ajax({
        type: 'GET',
        url: '/sys_list',
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            var order = data['order'];
            var systems = data['systems'];

            // save the order for use in systemSelect
            ui_data['system_order'] = order;

            // store current and empty
            var selected = $('#system_select').val();
            $('#system_select').empty();

            // add placeholder
            var empty_opt = $('<option></option>');
            empty_opt.text('--');
            empty_opt.val('--');
            $('#system_select').append(empty_opt);

            // add systems
            for(var idx in systems) {
                var system = systems[idx];
                var opt = $('<option></option>');
                opt.text(system['name']);
                opt.val(system['_id']);
                opt.addClass('system_option');
                opt.data('system', system);
                $('#system_select').append(opt);
            }

            // restore current
            var child = $('#system_select').children('[value='+selected+']');
            if(!empty_list && child.length == 1) {
                $('#system_select').val(selected);
            } else {
                emptySystem();
            }
        }
    });
}

function systemAdd() {
    var yaml = $("#system_add_yaml").val();
    $.ajax({
        type: 'POST',
        url: '/sys_add', 
        data: {'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var systemId = data['system_id'];
            console.log(systemId);
            // TODO: have sys_add return system_list so we don't make two requests
            systemList(true);
        }
    });
}

function systemSelect() {
    var option = $('#system_select').children(':selected');
    var system = option.data('system');

    if(system == undefined) {
        emptySystem();
        return;
    }

    var order = ui_data['system_order'];
    displayConfig(system, 'system', order, []);
    programList();
}

function systemDelete() {
    var system_id = $('#system_select').val();
    $.ajax({
        type: 'POST',
        url: '/sys_delete', 
        data: {'system_id': system_id}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            systemList(true);
        }
    });
}

function systemEdit(yaml) {
    var yaml = $("#system_edit_yaml").val();
    var system_id = $('#system_select').val();

    $.ajax({
        type: 'POST',
        url: '/sys_edit', 
        data: {'system_id': system_id, 'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var systemId = data['system_id'];
            // TODO: have sys_add return system_list so we don't make two requests
            systemList(true);
        }
    });
}

function systemInit() {
    $('#system_select').change(systemSelect);

    $("#system_add_btn").on('click', function() {
        $('.modal_content').hide();
        $('.sys_modal').hide();
        $('.sys_add').show();
        $('#modal_div').show();
    });

    $('#system_details_btn').on('click', function() {
        $('.modal_content').hide();
        $('.sys_modal').hide();
        $('.sys_info').show();
        $('#modal_div').show();
    });

    $("#system_save_btn").on('click', function() {
        if($('#system_edit_yaml').is(':visible')) {
            systemEdit();
        } else if($('#system_add_yaml').is(':visible')){
            systemAdd();    
        }
        $('#modal_div').hide();
    });

    $('#system_cancel_btn').on('click', function() {
        $('#modal_div').hide();
        $('.modal_content').hide();
    });

    $('#system_edit_btn').on('click', function() {
        $('.modal_content').hide();
        $('.sys_modal').hide();
        $('.sys_edit').show();
    });

    $("#system_delete_btn").on('click', function() {
        var msg = 'Delete the system, and all of the programs, runs, and crashes that belong to it.\n';
        msg += 'Are you sure?'

        if(confirm(msg)) {
            systemDelete();
            $('#modal_div').hide();
            $('.modal_content').hide();
        }
    });

    systemList();
}

/*
** PROGRAM
*/

function programList(empty_list=false) {
    var system_id = $('#system_select').val();
    if(system_id == '--')
        return;

    $.ajax({
        type: 'GET',
        url: '/prog_list/' + system_id,
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            var order_gui = data['order_gui'];
            var order_cmd = data['order_cmd'];
            var programs = data['programs'];

            // save the order for use in programSelect
            ui_data['program_order_gui'] = order_gui;
            ui_data['program_order_cmd'] = order_cmd;

            // store current and empty
            var selected = $('#program_select').val();
            $('#program_select').empty();

            // add placeholder
            var empty_opt = $('<option></option>');
            empty_opt.text('--');
            empty_opt.val('--');
            $('#program_select').append(empty_opt);

            // add programs
            for(var idx in programs) {
                var program = programs[idx];
                var opt = $('<option></option>');

                switch(program['_cls']) {
                    case 'Program.ProgramAutoIT':
                        var type = 'gui';
                        break;
                    case 'Program.ProgramCMD':
                        var type = 'cmd';
                        break;
                    default:
                        var type = 'unk';
                        brea
                }

                var prefix = '(' + type.toUpperCase() + ') ';
                opt.text(prefix + program['name']);
                opt.val(program['_id']);

                opt.data('program', program);
                opt.data('type', type);
                opt.addClass('program_option');

                $('#program_select').append(opt);
            }

            // restore current
            var child = $('#program_select').children('[value='+selected+']');
            if(!empty_list && child.length == 1) {
                $('#program_select').val(selected);
            } else {
                emptyProgram();
            }

        }
    });
}

function programAddGUI() {
    var yaml = $("#program_add_yaml").val();
    
    var system_id = $('#system_select').val();
    yaml += '\nsystem:\n';
    yaml += ' ' + system_id;
    
    $.ajax({
        type: 'POST',
        url: '/prog_add_gui', 
        data: {'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var programId = data['program_id'];
            // TODO: have prog_add return program_list so we don't make two requests
            programList(true);
        }
    });
}

function programAddCMD() {
    var yaml = $("#program_add_yaml").val();
    
    var system_id = $('#system_select').val();
    yaml += '\nsystem:\n';
    yaml += ' ' + system_id;

    $.ajax({
        type: 'POST',
        url: '/prog_add_cmd', 
        data: {'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var programId = data['program_id'];
            // TODO: have prog_add return program_list so we don't make two requests
            programList(true);
        }
    });
}

function programSelect() {
    var option = $('#program_select').children(':selected');
    var program = option.data('program');
    var type = option.data('type');

    if(program == undefined) {
        emptyProgram();
        return;
    }

    var order = ui_data['program_order_'+type];

    displayConfig(program, 'program', order, ['system']);
    runList();
}

function programDelete() {
    var program_id = $('#program_select').val();
    $.ajax({
        type: 'POST',
        url: '/prog_delete', 
        data: {'program_id': program_id}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            programList(true);
        }
    });
}

function programEdit(yaml) {
    var yaml = $("#program_edit_yaml").val();
    var program_id = $('#program_select').val();

    $.ajax({
        type: 'POST',
        url: '/prog_edit', 
        data: {'program_id': program_id, 'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var programId = data['program_id'];
            // TODO: have prog_add return program_list so we don't make two requests
            programList(true);
        }
    });
}

function programInit() {
    $('#program_select').change(programSelect);

    $("#program_add_btn").on('click', function() {
        $('.modal_content').hide();
        $('.prog_modal').hide();
        $('.prog_add').show();
        $('#modal_div').show();
    });

    $('#program_details_btn').on('click', function() {
        $('.modal_content').hide();
        $('.prog_modal').hide();
        $('.prog_info').show();
        $('#modal_div').show();
    });

    $("#program_save_btn").on('click', function() {
        if($('#program_edit_yaml').is(':visible')) {
            programEdit();
        }
        $('#modal_div').hide();
    });

    $('#program_cancel_btn').on('click', function() {
        $('#modal_div').hide();
        $('.modal_content').hide();
    });

    $('#program_edit_btn').on('click', function() {
        $('.modal_content').hide();
        $('.prog_modal').hide();
        $('.prog_edit').show();
    });

    $("#program_delete_btn").on('click', function() {
        var msg = 'Delete the program, and all of the runs and crashes that belong to it.\n';
        msg += 'Are you sure?'

        if(confirm(msg)) {
            programDelete();
            $('#modal_div').hide();
            $('.modal_content').hide();
        }
    });

    $("#program_add_gui_btn").on('click', function() {
        programAddGUI();    
    });

    $("#program_add_cmd_btn").on('click', function() {
        programAddCMD();    
    });

    // programList();
}

/*
** RUN
*/

function runList(empty_list=false) {
    var program_id = $('#program_select').val();
    if(program_id == '--')
        return;

    $.ajax({
        type: 'GET',
        url: '/run_list/' + program_id,
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            var order = data['order'];
            var runs = data['runs'];

            // save the order for use in runSelect
            ui_data['run_order'] = order;

            // store current and empty
            var selected = $('#run_select').val();
            $('#run_select').empty();

            // add placeholder
            var empty_opt = $('<option></option>');
            empty_opt.text('--');
            empty_opt.val('--');
            $('#run_select').append(empty_opt);

            // add runs
            for(var idx in runs) {
                var run = runs[idx];
                var opt = $('<option></option>');
                opt.text(run['name']);
                opt.val(run['_id']);
                opt.addClass('run_option');
                opt.data('run', run);
                $('#run_select').append(opt);
            }

            // restore current
            var child = $('#run_select').children('[value='+selected+']');
            if(!empty_list && child.length == 1) {
                $('#run_select').val(selected);
            } else {
                emptyRun();
            }
        }
    });
}

// select the last run and init its corpus
function initLastRun(empty_list=false) {
    var program_id = $('#program_select').val();
    if(program_id == '--')
        return;

    $.ajax({
        type: 'GET',
        url: '/run_list/' + program_id,
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            var order = data['order'];
            var runs = data['runs'];

            // save the order for use in runSelect
            ui_data['run_order'] = order;

            $('#run_select').empty();

            // add placeholder
            var empty_opt = $('<option></option>');
            empty_opt.text('--');
            empty_opt.val('--');
            $('#run_select').append(empty_opt);

            // add runs
            for(var idx in runs) {
                var run = runs[idx];
                var opt = $('<option></option>');
                opt.text(run['name']);
                opt.val(run['_id']);
                opt.addClass('run_option');
                opt.data('run', run);
                $('#run_select').append(opt);
            }
            // select last run
            $('#run_select option:last').prop('selected', true);

            // init the corpus
            runDefaultCorpus();
            runFilesList();
            corpusFilesList();

        }
    });
}



function runSelect() {
    var option = $('#run_select').children(':selected');
    var run = option.data('run');

    if(run == undefined) {
        emptyRun();
        return;
    }

    var order = ui_data['run_order'];
    displayConfig(run, 'run', order, ['program']);
    runFilesList();
    corpusFilesList();
}

function runAdd() {
    var yaml = $("#run_add_yaml").val();
    
    var run_type = $('#run_type_select').val();
    yaml += '\nrun_type:\n';
    yaml += ' ' + run_type;

    var program_id = $('#program_select').val();
    yaml += '\nprogram:\n';
    yaml += ' ' + program_id;
    
    $.ajax({
        type: 'POST',
        url: '/run_add', 
        data: {'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            runList(true);
        }
    });
}

// TODO: remove this
function runCreate() {
    var yaml = 'run_type:\n';
    yaml += ' all'

    var program_id = $('#program_select').val();
    yaml += '\nprogram:\n';
    yaml += ' ' + program_id;

    var mins = $('#mins').val();
    yaml += '\nmins:\n';
    yaml += ' ' + mins;

    var hours = $('#hours').val();
    yaml += '\nhours:\n';
    yaml += ' ' + hours;

    var number_workers = $('#number_workers').val();
    yaml += '\nnumber_workers:\n';
    yaml += ' ' + number_workers;
    
    $.ajax({
        type: 'POST',
        url: '/run_add', 
        data: {'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            initLastRun();
            
        }
    });

}

function runEdit(yaml) {
    var yaml = $("#run_edit_yaml").val();
    var runId = $('#run_select').val();

    $.ajax({
        type: 'POST',
        url: '/run_edit', 
        data: {'run_id': runId, 'yaml': yaml}, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            // TODO: have sys_add return system_list so we don't make two requests
            systemList(true);
        }
    });
}

// init the corpus
// Add all files with the targeted extension by default
function runDefaultCorpus() {
    var run_id = $('#run_select').val();
    console.log('Dans run default')
    console.log($('#run_select').val());
    console.log(run_id);
    
    console.log('Avant ajax run default')
    $.ajax({
        type: 'GET',
        url: '/run_default_corpus/' + $('#run_select').val(), 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            console.log(runId);
        }
    });
}

function runDetail() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'GET',
        url: '/_run_detail/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}

function runDelete() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_delete/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            $('#run_select option:first').prop('selected', true);
            runList(true);
        }
    });
}


function corpusFilesList() {
    $.ajax({
        type: 'GET',
        url: '/corpus_files_list', 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            
            $('#corpus_files_select').empty();

            for(var idx in data) {
                var file = data[idx];
                var opt = $('<option></option>');
                opt.text(file);
                opt.val(file);
                $('#corpus_files_select').append(opt);
            }
        }
    });
}

function runFilesList() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'GET',
        url: '/run_files_list/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            
            $('#run_files_select').empty();

            for(var idx in data) {
                var file = data[idx];
                var opt = $('<option></option>');
                opt.text(file);
                opt.val(file);
                $('#run_files_select').append(opt);
            }
        }
    });
}

function runFilesAdd() {
    var run_id = $('#run_select').val();
    var files = $('#corpus_files_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_files_add', 
        data: JSON.stringify({
            'run_id': run_id,
            'files': files,
        }), 
        dataType: "json",
        contentType: "application/json",
        success: function(data) {
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            console.log(runId);

            runFilesList();
        }
    });
}

function runFilesRemove() {
    var run_id = $('#run_select').val();
    var files = $('#run_files_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_files_remove', 
        data: JSON.stringify({
            'run_id': run_id,
            'files': files,
        }), 
        dataType: "json",
        contentType: "application/json",
        success: function(data) {
            if('error' in data) {
                handleError(data);
                return;
            } 
            var runId = data['run_id'];
            console.log(runId);

            runFilesList();
        }
    });
}

function runStart() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_start/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            console.log(data['run_id']);
        }
    });
}

function runStop() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_stop/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}

function runExploitable() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_exploitable/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}

function runStats() {
    var run_id = $('#run_select').val();
    $.ajax({
        type: 'GET',
        url: '/run_stats/' + run_id, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}


function runInit() {
    $('#run_select').change(runSelect);

    $("#run_add_btn").on('click', function() {
        $('.modal_content').hide();
        $('.run_modal').hide();
        $('.run_add').show();
        $('#modal_div').show();
    });

    $('#run_details_btn').on('click', function() {
        $('.modal_content').hide();
        $('.run_modal').hide();
        $('.run_info').show();
        $('#modal_div').show();
    });

    $("#run_save_btn").on('click', function() {
        if($('#run_edit_yaml').is(':visible')) {
            runEdit();
        } else if($('#run_add_yaml').is(':visible')){
            runAdd();    
        }
        $('#modal_div').hide();
    });

    $('#run_cancel_btn').on('click', function() {
        $('#modal_div').hide();
        $('.modal_content').hide();
    });

    $('#run_edit_btn').on('click', function() {
        $('.modal_content').hide();
        $('.run_modal').hide();
        $('.run_edit').show();
    });

    $("#run_delete_btn").on('click', function() {
        var msg = 'Delete the run and all crashes that belong to it.\n';
        msg += 'Are you sure?'

        if(confirm(msg)) {
            runDelete();
            $('#modal_div').hide();
            $('.modal_content').hide();
        }
    });

    //

    $("#run_start_btn").on('click', function() {
        runStart(); 
    });

    $("#run_stop_btn").on('click', function() {
        runStop();  
    });

    // $("#run_exploitable_btn").on('click', function() {
    //     runExploitable();   
    // });
    
    $('#run_file_add_btn').on('click', function() {
        runFilesAdd();
    });

    $('#run_file_remove_btn').on('click', function() {
        runFilesRemove();
    });

    // runList();
}

/*
** MISC
*/

function displayConfig(config, prefix, order, skip) {
    console.log(order);
    var id_prefix = '#' + prefix;
    var yaml = '';

    $(id_prefix+'_info_div').empty();
    for(var idx in order) {
        var key = order[idx];
        if(skip.indexOf(key) > -1)
            continue;

        var value = config[key];

        var label = $('<h3></h3>');
        label.text(key);
        $(id_prefix+'_info_div').append(label);

        if(typeof(value) == 'string' 
            || typeof(value) == 'boolean'
            || typeof(value) == 'number') {
            yaml += key + ':\n';
            if(typeof(value) == 'string')
                yaml += ' \'' + value + '\'\n';
            else
                yaml += ' ' + value + '\n';

            var content = $('<div></div>');
            content.addClass('config_content');
            content.text(value);
            $(id_prefix+'_info_div').append(content);
        } else if(typeof(value) == 'object' && Array.isArray(value)) {
            console.log(value);
            yaml += key + ':\n';

            for(var idx in value) {
                var content = $('<div></div>');
                content.addClass('config_content');
                content.text(value[idx]);
                $(id_prefix+'_info_div').append(content);
                yaml += ' - \'' + value[idx] + '\'\n';
            }
        } 
    }
    $(id_prefix+'_edit_yaml').val(yaml);
}

function emptyRun() {
    $('#run_add_yaml').val('');
    $('#run_info_div').empty();
    $('#run_edit_yaml').val('');
    $('#run_files_select').empty();
}

function emptyProgram() {
    $('#program_add_yaml').val('');
    $('#program_info_div').empty();
    $('#program_edit_yaml').val('');
    $('.run_option').remove();
    emptyRun();
}

function emptySystem() {
    $('#system_add_yaml').val('');
    $('#system_info_div').empty();
    $('#system_edit_yaml').val('');
    $('.program_option').remove();
    emptyProgram();
}

function handleError(data) {
    console.log('ERROR: ', data['message']);
    $('#error_span').text(data['message']);
    $('#error_div').show();
}

function modalInit() {
    $('#modal_div').hide();
    
    $('#modal_div').on('click', function() { 
        $('#modal_div').hide(); 
    });

    $('.modal_content').on('click', function(e) {
        e.stopPropagation();
    });
}

$(document).ready(function() {
    $('#error_div').hide();
    
    $('#error_dismiss_btn').on('click', function() {
        $('#error_div').hide();
    });

    systemInit();
    programInit();
    runInit();
    modalInit();
});

/* OLD */

function pollTask(taskId) {
    $.ajax({
        type: 'GET',
        url: '/task_status/' + taskId,
        success: function(data) {
            console.log(data);
            if(data == 'PENDING') {
                setTimeout(function() {
                    pollTask(taskId);
                }, 500);
            } else {
                fetchJobs();
            }
        }
    });
}
