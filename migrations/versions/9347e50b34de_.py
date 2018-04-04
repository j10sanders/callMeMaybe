"""empty message

Revision ID: 9347e50b34de
Revises: 7776d9f40708
Create Date: 2018-04-02 12:55:10.019181

"""

# revision identifiers, used by Alembic.
revision = '9347e50b34de'
down_revision = '7776d9f40708'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('email', sa.String(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'email')
    ### end Alembic commands ###