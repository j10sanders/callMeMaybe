"""empty message

Revision ID: bef9603a8e48
Revises: fc8a248e7a90
Create Date: 2018-04-26 12:43:21.183869

"""

# revision identifiers, used by Alembic.
revision = 'bef9603a8e48'
down_revision = 'fc8a248e7a90'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('discussion_profiles', sa.Column('front_page', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('discussion_profiles', 'front_page')
    ### end Alembic commands ###
