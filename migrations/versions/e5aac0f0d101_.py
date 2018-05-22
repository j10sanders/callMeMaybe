"""empty message

Revision ID: e5aac0f0d101
Revises: 6ade36e4d4b6
Create Date: 2018-05-22 08:32:20.063160

"""

# revision identifiers, used by Alembic.
revision = 'e5aac0f0d101'
down_revision = '6ade36e4d4b6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('accepted_terms', sa.Boolean(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'accepted_terms')
    ### end Alembic commands ###
