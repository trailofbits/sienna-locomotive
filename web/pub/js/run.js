/*
** RUN
*/

function runList(empty_list=false, programId, selectId, showRun=false) {
    if(programId == undefined)
        programId = $('#program_select').val();
    if(programId == '--') 
        return;

    $.ajax({
        type: 'GET',
        url: '/run_list/' + programId,
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

            if(selectId != undefined) {
                $('#run_select').val(selectId);
                runSelect();
                if(showRun) {
                    $('#run_details_btn').trigger('click');
                }
            }
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
    runStats();
}

function runAdd() {
    var yaml = $("#run_add_yaml").val();
    
    var run_type = $('#run_type_select').val();
    yaml += '\nrun_type:\n';
    yaml += ' ' + run_type;

    var program_id = $('#program_select').val();
    yaml += '\nprogram:\n';
    yaml += ' ' + program_id;

    if(program_id == '--') {
        handleError({'message': 'Please select a program.'});
        return;
    }
    
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
            runList(true, undefined, runId, true);
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

function runDelete() {
    var runId = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_delete/' + runId, 
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

function runFilesList() {
    var runId = $('#run_select').val();
    $.ajax({
        type: 'GET',
        url: '/run_files_list/' + runId, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            
            $('#run_files_select').empty();

            if(data.length < 1) {
                $('#run_files_header').css('color', 'red');
            } else {
                $('#run_files_header').css('color', 'black');
            }

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
    var runId = $('#run_select').val();
    var files = $('#corpus_files_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_files_add', 
        data: JSON.stringify({
            'run_id': runId,
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
            runFilesList();
        }
    });
}

function runFilesRemove() {
    var runId = $('#run_select').val();
    var files = $('#run_files_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_files_remove', 
        data: JSON.stringify({
            'run_id': runId,
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
            runFilesList();
        }
    });
}

function runStart() {
    var runId = $('#run_select').val();

    if(runId == '--') {
        handleError({'message':'Please make a selection.'});
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/run_start/' + runId, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
            runStats(data['run_id'])
        }
    });
}

function runStop() {
    var runId = $('#run_select').val();

    if(runId == '--') {
        handleError({'message':'Please make a selection.'});
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/run_stop/' + runId, 
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
        if($('#run_select').val() == '--') {
            handleError({'message': 'Please make a selection.'})
            return;
        }
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

function runsActive() {
    $.ajax({
        type: 'GET',
        url: '/run_active_list', 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}

function runsComplete() {
    $.ajax({
        type: 'GET',
        url: '/run_complete_list', 
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
    var runId = $('#run_select').val();
    $.ajax({
        type: 'POST',
        url: '/run_exploitable/' + runId, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 
        }
    });
}