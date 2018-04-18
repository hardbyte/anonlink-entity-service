from marshmallow import Schema, fields


class SchemaSchema(Schema):
    pass


class NewProjectSchema(Schema):
    name = fields.Str()
    notes = fields.Str()
    number_parties = fields.Integer()
    result_type = fields.Str()
    schema = fields.Nested(SchemaSchema())


class ProjectDescription(NewProjectSchema):
    project_id = fields.Str()


class ProjectListSummary(Schema):
    project_id = fields.Str()
    time_added = fields.DateTime()

