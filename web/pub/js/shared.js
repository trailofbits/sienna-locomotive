/*
** GLOBAL
*/

window.ui_data = {}

/*
** MISC
*/

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

    visReady();
});