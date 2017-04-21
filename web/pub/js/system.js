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
            // TODO: have sys_add return system_list so we don't make two requests
            systemList(true);
        }
    });
}

function systemSelect(list=true) {
    var option = $('#system_select').children(':selected');
    var system = option.data('system');

    if(system == undefined) {
        emptySystem();
        return;
    }

    var order = ui_data['system_order'];
    displayConfig(system, 'system', order, []);
    if(list)
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
        if($('#system_select').val() == '--') {
            handleError({'message': 'Please make a selection.'})
            return;
        }
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