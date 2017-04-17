/*
** PROGRAM
*/

function programList(empty_list=false, systemId, selectId) {
    if(systemId == undefined)
        systemId = $('#system_select').val();

    if(systemId == '--')
        return;

    $.ajax({
        type: 'GET',
        url: '/prog_list/' + systemId,
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

            if(selectId != undefined) {
                $('#program_select').val(selectId);
                programSelect(false);
            }
        }
    });
}

function programAddGUI() {
    var yaml = $("#program_add_yaml").val();
    
    var systemId = $('#system_select').val();
    yaml += '\nsystem:\n';
    yaml += ' ' + systemId;
    
    if(systemId == '--') {
        handleError({'message': 'Please select a system.'});
        return;
    }

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
    
    var systemId = $('#system_select').val();
    yaml += '\nsystem:\n';
    yaml += ' ' + systemId;

    if(systemId == '--') {
        handleError({'message': 'Please select a system.'});
        return;
    }

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

function programSelect(list=true) {
    var option = $('#program_select').children(':selected');
    var program = option.data('program');
    var type = option.data('type');

    if(program == undefined) {
        emptyProgram();
        return;
    }

    var order = ui_data['program_order_'+type];

    displayConfig(program, 'program', order, ['system']);
    if(list)
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
        if($('#program_select').val() == '--') {
            handleError({'message': 'Please make a selection.'})
            return;
        }
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