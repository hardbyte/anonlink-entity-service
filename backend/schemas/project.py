from marshmallow import Schema, fields


class SchemaSchema(Schema):
    pass


class NewProjectSchema(Schema):

    name = fields.Str()
    result_type = fields.Str()

    schema = fields.Nested(SchemaSchema())
