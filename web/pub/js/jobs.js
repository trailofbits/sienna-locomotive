function removeWinaflJob(id) {
	$.ajax({
		type: 'POST',
		url: '/winafl_job_remove', 
		data: {'id': id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			listWinaflJobs(data);
		}
	});
}

function getModOffWinaflJob(id) {
	$.ajax({
		type: 'POST',
		url: 'winafl_job_mod_off', 
		data: {'id': id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			listWinaflJobs(data);
		}
	});
}

function listWinaflJobs(results) {
	var body = $("#winafl_job_list_body");
	body.empty();
	var keys = schema['winafl_job']['order'];
	for(var ridx in results) {
		var result = results[ridx];
		var row = $('<tr></tr>')
		for(kidx in keys) {
			var col = $('<td></td>');
			var key = keys[kidx];
			col.text(result[key]);
			row.append(col);
		}
		var editButton = $('<button>Edit</button>');
		var removeButton = $('<button>Remove</button>');
		// row.append(editButton);
		row.append(removeButton);
		removeButton.on('click', function() {
			var row = $(this).parent();
			var id = row.children().first().text();
			console.log(id);
			removeWinaflJob(id);
		});
		body.append(row);

		var modoffButton = $('<button></button>');
		modoffButton.text('Mod Off');
		modoffButton.on('click', function() {
			var data = {};
			var id = row.children().first().text();
			getModOffWinaflJob(id);
		});
		row.append(modoffButton);
	}
}

function handleError(data) {
	console.log('ERROR: ', data['message']);
}

function fetchJobs() {
	$.getJSON('/winafl_job_list', listWinaflJobs);
}

function buildJob(schema, schemaKey) {
	var idBase = schemaKey;
	var idAdd = idBase + '_add';
	var idList = idBase + '_list';
	var keys = schema[schemaKey]['order'];

	for(var idx in keys) {
		var key = keys[idx];
		var type = schema[schemaKey][key]['type'];
		var required = schema[schemaKey][key]['required'];
		var colName = keys[idx];
		if(colName != 'id') {
			var addLabel = $('<label></label>');
			switch(type) {
				case 'text':
					var addInput = $('<textarea></textarea>');
					break;
				case 'str':
					var addInput = $('<input></input>');
					addInput.attr('type', 'text');
					break;
				case 'num':
					var addInput = $('<input></input>');
					addInput.attr('type', 'number');
					break;
				default:
					var addInput = $('<input></input>');
					break;
			}
			var idAddInput = idBase + '_input_' + colName;
			
			addLabel.attr('for', idAddInput);
			var req = required ? '*' : '';
			addLabel.text(colName + req);

			addInput.attr('id', idAddInput);
			addInput.attr('name', colName);
			$('#' + idAdd).append(addLabel);
			$('#' + idAdd).append($('<br/>'));

			$('#' + idAdd).append(addInput);
			$('#' + idAdd).append($('<br/>'));
		}

		var colHead = $('<td></td>');
		colHead.text(colName);
		$('#' + idList + '_head_row').append(colHead);
	}

	var addButton = $('<button></button>');
	addButton.attr('id', idAdd + '_btn');
	addButton.text('Create');
	addButton.on('click', function() {
		var data = {};
		for(var idx in keys) {
			var key = keys[idx];
			if(key == 'id') {
				continue;
			}

			data[key] = $('#' + idBase + '_input_' + key).val();
		}
		var endpoint = '/' + idBase + '_create';
		$.ajax({
			type: 'POST',
			url: endpoint, 
			data: data, 
			success: function(data) {
				data = JSON.parse(data);
				if('error' in data) {
					handleError(data);
					return;
				} 
				listWinaflJobs(data);
			}
		});
		console.log(data);
	});
	$('#' + idAdd).append(addButton);
}

function buildElements() {
	for(var key in schema) {
		if(key.indexOf('job') > -1) {
			buildJob(schema, key);
		}
	}
}

function initPage() {
	$.getJSON('/schema', function(results) {
		schema = results;
		buildElements();
	});
}

$(document).ready(function() {
	initPage();
	fetchJobs();
});
